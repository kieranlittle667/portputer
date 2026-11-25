//! End-to-end secure input. The normal server relays opaque frames only.
//! Enrollment requires confirmation on the device and by an elevated UI.
use crate::{Error, protocol::ClientMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::{HandshakeState, TransportState};

pub const VERSION: u32 = 2;
pub const MAX_FRAME: usize = 12 * 1024;
pub const MAX_SESSIONS: usize = 8;
pub const ENROLL_SECONDS: u64 = 120;
const PROLOGUE: &[u8] = b"portputer secure input 2";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Input {
    Key {
        code: String,
        down: bool,
        repeat: bool,
    },
    Tap {
        code: String,
        modifiers: Vec<String>,
    },
    Text {
        text: String,
    },
    Release,
}
impl Input {
    pub fn from_message(message: &ClientMessage) -> Option<Self> {
        match message {
            ClientMessage::Key { code, down, repeat } => Some(Self::Key {
                code: code.clone(),
                down: *down,
                repeat: *repeat,
            }),
            ClientMessage::Tap { code, modifiers } => Some(Self::Tap {
                code: code.clone(),
                modifiers: modifiers.clone(),
            }),
            ClientMessage::Text { text } => Some(Self::Text { text: text.clone() }),
            ClientMessage::ReleaseAll => Some(Self::Release),
            _ => None,
        }
    }
    pub fn valid(&self) -> bool {
        match self {
            Self::Key { code, .. } => crate::keys::by_code(code).is_some(),
            Self::Tap { code, modifiers } => {
                crate::keys::by_code(code).is_some()
                    && modifiers.len() <= 8
                    && modifiers.iter().all(|m| crate::keys::is_modifier(m))
            }
            Self::Text { text } => text.len() <= 8000,
            Self::Release => true,
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Payload {
    Confirm,
    Input { input: Input },
    Ready { trusted: bool },
    Ack { accepted: bool },
}

/// Only these ciphertext frames pass through the unprivileged application.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum RelayRequest {
    Open { version: u32, enroll: bool },
    Frame { frame: Vec<u8> },
    Status,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayReply {
    pub version: u32,
    pub secure_desktop: bool,
    #[serde(default)]
    pub opened: bool,
    pub frame: Option<Vec<u8>>,
    /// Decrypted only while the service observes Default. The ordinary app
    /// posts it at its own integrity level and removes it before forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal_input: Option<Input>,
}
/// Implemented by the Windows application; core has no helper dependency.
pub trait Relay: Send + Sync {
    fn connect(&self) -> Result<Box<dyn RelayConnection>, String>;
}
pub trait RelayConnection: Send {
    fn exchange(&mut self, request: RelayRequest) -> Result<RelayReply, String>;
}

pub struct Handshake {
    state: HandshakeState,
}
pub struct Channel {
    state: TransportState,
    pub peer: [u8; 32],
    pub hash: Vec<u8>,
}
impl Handshake {
    pub fn new(private: &[u8; 32], initiator: bool) -> Result<Self, Error> {
        let builder = crate::transport::builder()
            .local_private_key(private)?
            .prologue(PROLOGUE)?;
        Ok(Self {
            state: if initiator {
                builder.build_initiator()?
            } else {
                builder.build_responder()?
            },
        })
    }
    pub fn write(&mut self) -> Result<Vec<u8>, Error> {
        let mut frame = vec![0; MAX_FRAME];
        let n = self.state.write_message(&[], &mut frame)?;
        frame.truncate(n);
        Ok(frame)
    }
    pub fn read(&mut self, frame: &[u8]) -> Result<(), Error> {
        if frame.len() > MAX_FRAME {
            return Err(Error::Protocol("secure frame too large".into()));
        }
        let mut plain = vec![0; MAX_FRAME];
        if self.state.read_message(frame, &mut plain)? != 0 {
            return Err(Error::Protocol("unexpected handshake payload".into()));
        }
        Ok(())
    }
    pub fn finished(&self) -> bool {
        self.state.is_handshake_finished()
    }
    pub fn finish(self) -> Result<Channel, Error> {
        let peer = self
            .state
            .get_remote_static()
            .and_then(|p| p.try_into().ok())
            .ok_or_else(|| Error::Protocol("missing secure peer key".into()))?;
        let hash = self.state.get_handshake_hash().to_vec();
        Ok(Channel {
            peer,
            hash,
            state: self.state.into_transport_mode()?,
        })
    }
}
impl Channel {
    pub fn comparison(&self) -> String {
        let hash = Sha256::digest(
            [
                b"portputer secure input comparison 2".as_slice(),
                &self.hash,
            ]
            .concat(),
        );
        format!(
            "{:06}",
            u32::from_be_bytes(hash[..4].try_into().unwrap()) % 1_000_000
        )
    }
    pub fn seal(&mut self, payload: &Payload) -> Result<Vec<u8>, Error> {
        let plain = serde_json::to_vec(payload)?;
        if plain.len() + 16 > MAX_FRAME {
            return Err(Error::Protocol("secure payload too large".into()));
        }
        let mut out = vec![0; plain.len() + 16];
        let n = self.state.write_message(&plain, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
    pub fn open(&mut self, frame: &[u8]) -> Result<Payload, Error> {
        if frame.len() > MAX_FRAME {
            return Err(Error::Protocol("secure frame too large".into()));
        }
        let mut out = vec![0; frame.len()];
        let n = self.state.read_message(frame, &mut out)?;
        Ok(serde_json::from_slice(&out[..n])?)
    }
}

/// The service's authorization state for one completed handshake. Callers
/// must destroy it on any protocol error, timeout, disconnect or disable.
pub struct Authorization {
    pub channel: Channel,
    trusted: bool,
    local_confirmed: bool,
    device_confirmed: bool,
    created: std::time::Instant,
}
impl Authorization {
    pub fn new(channel: Channel, trusted: bool) -> Self {
        Self {
            channel,
            trusted,
            local_confirmed: false,
            device_confirmed: false,
            created: std::time::Instant::now(),
        }
    }
    pub fn expired(&self) -> bool {
        !self.trusted && self.created.elapsed().as_secs() >= ENROLL_SECONDS
    }
    pub fn approve(&mut self, hash: &[u8]) -> bool {
        if self.expired() || !crate::identity::constant_time_eq(hash, &self.channel.hash) {
            return false;
        }
        self.local_confirmed = true;
        true
    }
    pub fn receive(&mut self, frame: &[u8]) -> Result<Option<Input>, Error> {
        if self.expired() {
            return Err(Error::Refused("secure enrollment expired".into()));
        }
        match self.channel.open(frame)? {
            Payload::Confirm if !self.trusted => {
                self.device_confirmed = true;
                Ok(None)
            }
            Payload::Input { input } if self.trusted && input.valid() => Ok(Some(input)),
            _ => Err(Error::Refused("secure input is not authorized".into())),
        }
    }
    pub fn needs_commit(&self) -> bool {
        !self.expired() && !self.trusted && self.local_confirmed && self.device_confirmed
    }
    /// Only after the protected store has been successfully written.
    pub fn committed(&mut self) {
        if self.needs_commit() {
            self.trusted = true;
        }
    }
    pub fn trusted(&self) -> bool {
        self.trusted
    }
}

/// Client state belongs to one outer control connection and is discarded on
/// reconnect. No input is queued across handshakes or retried after failure.
pub struct Device {
    private: [u8; 32],
    handshake: Option<Handshake>,
    channel: Option<Channel>,
    pin: Option<[u8; 32]>,
    pin_invalid: bool,
    pin_path: std::path::PathBuf,
    enroll: bool,
    confirmed: bool,
    ready: bool,
    challenged: bool,
    opening: bool,
}
impl Device {
    pub fn new(private: [u8; 32], directory: &std::path::Path, server_id: &str) -> Self {
        // Server IDs are a public-key hash; never use a network name as a path.
        let name = hex::encode(Sha256::digest(server_id.as_bytes()));
        let pin_path = directory.join("secure-input").join(name);
        let (pin, pin_invalid) = match std::fs::read(&pin_path) {
            Ok(bytes) => match bytes.try_into() {
                Ok(key) => (Some(key), false),
                Err(_) => (None, true),
            },
            Err(error) => (None, error.kind() != std::io::ErrorKind::NotFound),
        };
        Self {
            private,
            handshake: None,
            channel: None,
            pin,
            pin_invalid,
            pin_path,
            enroll: false,
            confirmed: false,
            ready: false,
            challenged: false,
            opening: false,
        }
    }
    pub fn start(&mut self, enroll: bool) -> RelayRequest {
        self.handshake = None;
        self.channel = None;
        self.ready = false;
        self.confirmed = false;
        self.enroll = enroll;
        self.challenged = false;
        self.opening = true;
        RelayRequest::Open {
            version: VERSION,
            enroll,
        }
    }
    /// Returns another ciphertext frame and an optional locally derived
    /// comparison number. A server-supplied string is never used as that number.
    pub fn receive(
        &mut self,
        reply: RelayReply,
    ) -> Result<(Option<RelayRequest>, Option<String>), Error> {
        if reply.version != VERSION {
            return Err(Error::Refused("Secure-input helper needs updating.".into()));
        }
        if self.opening {
            // Drain replies from the old session before starting a replacement.
            if !reply.opened {
                return Ok((None, None));
            }
            self.opening = false;
            let mut hs = Handshake::new(&self.private, true)?;
            let frame = hs.write()?;
            self.handshake = Some(hs);
            return Ok((Some(RelayRequest::Frame { frame }), None));
        }
        let Some(frame) = reply.frame else {
            return Ok((None, None));
        };
        if let Some(mut hs) = self.handshake.take() {
            hs.read(&frame)?;
            let frame = hs.write()?;
            let channel = hs.finish()?;
            if !self.enroll && self.pin != Some(channel.peer) {
                return Err(Error::Refused(
                    "This secure-input service has not been enrolled on this device.".into(),
                ));
            }
            self.channel = Some(channel);
            return Ok((Some(RelayRequest::Frame { frame }), None));
        }
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| Error::Protocol("unexpected secure frame".into()))?;
        match channel.open(&frame)? {
            Payload::Ready { trusted } => {
                if trusted {
                    if self.enroll {
                        if !self.confirmed {
                            return Err(Error::Refused(
                                "Secure enrollment was not confirmed on this device.".into(),
                            ));
                        }
                        let directory = self.pin_path.parent().unwrap();
                        std::fs::create_dir_all(directory)?;
                        std::fs::write(&self.pin_path, channel.peer)?;
                        self.pin = Some(channel.peer);
                        self.pin_invalid = false;
                        self.enroll = false;
                    }
                    if self.pin != Some(channel.peer) {
                        return Err(Error::WrongServer);
                    }
                    self.ready = true;
                } else if !self.enroll {
                    return Err(Error::Refused(
                        "This device is not allowed on secure screens.".into(),
                    ));
                }
                if self.enroll && !trusted && !self.challenged {
                    self.challenged = true;
                    return Ok((None, Some(channel.comparison())));
                }
            }
            Payload::Ack { .. } => {}
            _ => return Err(Error::Protocol("unexpected secure response".into())),
        }
        Ok((None, None))
    }
    pub fn confirm(&mut self, comparison: &str) -> Result<RelayRequest, Error> {
        let channel = self.channel.as_mut().ok_or(Error::Closed)?;
        if !self.enroll || self.ready || !self.challenged || comparison != channel.comparison() {
            return Err(Error::Refused(
                "Secure enrollment comparison changed.".into(),
            ));
        }
        self.confirmed = true;
        Ok(RelayRequest::Frame {
            frame: channel.seal(&Payload::Confirm)?,
        })
    }
    pub fn input(&mut self, input: Input) -> Result<Option<Vec<RelayRequest>>, Error> {
        if !self.ready
            && !self.requires_secure()
            && !self.enroll
            && self.handshake.is_none()
            && self.channel.is_none()
        {
            return Ok(None);
        }
        if !self.ready || !input.valid() {
            return Err(Error::Refused(
                "Secure-screen input is unavailable for this device.".into(),
            ));
        }
        let channel = self.channel.as_mut().ok_or(Error::Closed)?;
        let inputs = if let Input::Text { text } = input {
            // JSON escaping can expand a character by six bytes. Bound each
            // encrypted piece without changing the ordinary text path.
            let mut inputs = Vec::new();
            let mut piece = String::new();
            for ch in text.chars() {
                if piece.len() + ch.len_utf8() > 1024 {
                    inputs.push(Input::Text {
                        text: std::mem::take(&mut piece),
                    });
                }
                piece.push(ch);
            }
            if !piece.is_empty() {
                inputs.push(Input::Text { text: piece });
            }
            inputs
        } else {
            vec![input]
        };
        inputs
            .into_iter()
            .map(|input| {
                channel
                    .seal(&Payload::Input { input })
                    .map(|frame| RelayRequest::Frame { frame })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }
    /// Only an explicit choice in the controlling device's UI may remove
    /// the pin. A server notice or missing capability must never do this.
    pub fn use_normal_keyboard(&mut self) -> Result<(), Error> {
        match std::fs::remove_file(&self.pin_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.pin = None;
        self.pin_invalid = false;
        self.channel = None;
        self.handshake = None;
        self.ready = false;
        self.enroll = false;
        self.opening = false;
        Ok(())
    }
    pub fn requires_secure(&self) -> bool {
        self.pin.is_some() || self.pin_invalid
    }
    pub fn ready(&self) -> bool {
        self.ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn channels() -> (Channel, Channel) {
        let a = crate::transport::builder().generate_keypair().unwrap();
        let b = crate::transport::builder().generate_keypair().unwrap();
        let mut a = Handshake::new(a.private.as_slice().try_into().unwrap(), true).unwrap();
        let mut b = Handshake::new(b.private.as_slice().try_into().unwrap(), false).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        a.read(&b.write().unwrap()).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        (a.finish().unwrap(), b.finish().unwrap())
    }
    #[test]
    fn escaped_text_is_split_without_changing_content() {
        let (a, mut b) = channels();
        let mut device = Device::new([0; 32], std::path::Path::new("."), "text-test");
        device.channel = Some(a);
        device.ready = true;
        let text = "\n".repeat(8000);
        let frames = device
            .input(Input::Text { text: text.clone() })
            .unwrap()
            .unwrap();
        let mut received = String::new();
        for frame in frames {
            let RelayRequest::Frame { frame } = frame else {
                panic!("expected ciphertext")
            };
            assert!(frame.len() <= MAX_FRAME);
            let Payload::Input {
                input: Input::Text { text },
            } = b.open(&frame).unwrap()
            else {
                panic!("expected text")
            };
            received.push_str(&text);
        }
        assert_eq!(received, text);
    }
    #[test]
    fn enrolled_device_cannot_fall_back_to_plaintext_when_service_is_unavailable() {
        let mut device = Device::new([0; 32], std::path::Path::new("."), "downgrade-test");
        assert!(device.input(Input::Release).unwrap().is_none());
        device.pin_invalid = true;
        assert!(device.input(Input::Release).is_err());
        device.use_normal_keyboard().unwrap();
        device.pin = Some([1; 32]);
        assert!(device.input(Input::Release).is_err());
        device.use_normal_keyboard().unwrap();
        assert!(device.input(Input::Release).unwrap().is_none());
        device.start(true);
        assert!(device.input(Input::Release).is_err());
    }
    #[test]
    fn normal_desktop_hint_cannot_disable_encryption() {
        let (a, mut b) = channels();
        let mut device = Device::new([0; 32], std::path::Path::new("."), "hint-test");
        device.channel = Some(a);
        device.ready = true;
        let ready = b.seal(&Payload::Ready { trusted: true }).unwrap();
        device.pin = Some(device.channel.as_ref().unwrap().peer);
        device
            .receive(RelayReply {
                version: VERSION,
                secure_desktop: false,
                opened: false,
                frame: Some(ready),
                normal_input: None,
            })
            .unwrap();
        let frames = device.input(Input::Release).unwrap().unwrap();
        let RelayRequest::Frame { frame } = &frames[0] else {
            panic!("expected ciphertext")
        };
        assert!(matches!(
            b.open(frame).unwrap(),
            Payload::Input {
                input: Input::Release
            }
        ));
    }
    #[test]
    fn comparison_is_bound_to_both_handshakes() {
        let (a, b) = channels();
        assert_eq!(a.comparison(), b.comparison());
        assert_eq!(a.hash, b.hash);
        let (c, _) = channels();
        assert_ne!(a.hash, c.hash);
    }
    #[test]
    fn enrollment_requires_both_confirmations_and_store_commit() {
        let (mut a, b) = channels();
        let hash = b.hash.clone();
        let mut auth = Authorization::new(b, false);
        assert!(auth.approve(&hash));
        assert!(!auth.needs_commit());
        assert!(!auth.trusted());
        auth.receive(&a.seal(&Payload::Confirm).unwrap()).unwrap();
        assert!(auth.needs_commit());
        assert!(!auth.trusted());
        auth.committed();
        assert!(auth.trusted());
        let input = Input::Key {
            code: "KeyA".into(),
            down: true,
            repeat: false,
        };
        assert_eq!(
            auth.receive(
                &a.seal(&Payload::Input {
                    input: input.clone()
                })
                .unwrap()
            )
            .unwrap(),
            Some(input)
        );
    }
    #[test]
    fn device_confirmation_alone_cannot_enroll() {
        let (mut a, b) = channels();
        let mut auth = Authorization::new(b, false);
        auth.receive(&a.seal(&Payload::Confirm).unwrap()).unwrap();
        auth.committed();
        assert!(!auth.trusted());
        assert!(!auth.approve(&[0; 32]));
        assert!(!auth.trusted());
    }
    #[test]
    fn unknown_device_cannot_inject() {
        let (mut a, b) = channels();
        let mut auth = Authorization::new(b, false);
        assert!(
            auth.receive(
                &a.seal(&Payload::Input {
                    input: Input::Release
                })
                .unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn tampering_replay_and_other_session_fail() {
        let (mut a, mut b) = channels();
        let frame = a.seal(&Payload::Confirm).unwrap();
        let mut corrupt = frame.clone();
        corrupt[0] ^= 1;
        assert!(b.open(&corrupt).is_err());
        assert!(b.open(&frame).is_ok());
        assert!(b.open(&frame).is_err());
        let (_, mut c) = channels();
        assert!(c.open(&frame).is_err());
    }
    #[test]
    fn rejects_large_frames_and_invalid_inputs() {
        let (_, mut b) = channels();
        assert!(b.open(&vec![0; MAX_FRAME + 1]).is_err());
        assert!(
            !Input::Key {
                code: "Shell".into(),
                down: true,
                repeat: false
            }
            .valid()
        );
        assert!(
            !Input::Text {
                text: "x".repeat(8001)
            }
            .valid()
        );
        assert!(
            !Input::Tap {
                code: "KeyA".into(),
                modifiers: vec!["KeyB".into()]
            }
            .valid()
        );
    }
    #[test]
    fn expired_enrollment_cannot_be_confirmed() {
        let (mut a, b) = channels();
        let hash = b.hash.clone();
        let mut auth = Authorization::new(b, false);
        auth.created = std::time::Instant::now() - std::time::Duration::from_secs(ENROLL_SECONDS);
        assert!(!auth.approve(&hash));
        assert!(auth.receive(&a.seal(&Payload::Confirm).unwrap()).is_err());
    }
}
