//! Windows secure-input service and ciphertext-only local relay.
pub use portputer_core::secure_input::{MAX_FRAME, RelayReply, RelayRequest, VERSION};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Request {
    Relay { request: RelayRequest },
    BeginEnrollment,
    Pending,
    Approve { hash: Vec<u8> },
    CancelEnrollment,
    Disable,
    UpdateBegin { size: u64, signature: String },
    UpdateChunk { bytes: Vec<u8> },
    UpdateFinish,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub hash: Vec<u8>,
    pub comparison: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub version: u32,
    pub ok: bool,
    pub relay: Option<RelayReply>,
    pub pending: Option<Pending>,
}
impl Reply {
    pub fn new(ok: bool) -> Self {
        Self {
            version: VERSION,
            ok,
            relay: None,
            pending: None,
        }
    }
}
#[cfg(windows)]
pub mod setup;
#[cfg(windows)]
pub mod update;
#[cfg(windows)]
pub mod win;
