//! Bounded overlapped pipe transport. The pipe carries ciphertext, not input.
use crate::{MAX_FRAME, Reply, Request, VERSION};
use portputer_core::secure_input::{Relay, RelayConnection, RelayReply, RelayRequest};
use std::{
    io,
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::Authorization::*,
    Security::*,
    System::Com::CoTaskMemFree,
    System::{RemoteDesktop::ProcessIdToSessionId, Threading::*},
    UI::Shell::*,
};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub fn session_id() -> io::Result<u32> {
    let mut id = 0;
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut id) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(id)
    }
}
pub fn known_folder(id: &windows_sys::core::GUID) -> io::Result<PathBuf> {
    unsafe {
        let mut path = std::ptr::null_mut();
        let hr = SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut path);
        if hr < 0 {
            return Err(io::Error::other("Windows known folder unavailable"));
        }
        let mut len = 0;
        while *path.add(len) != 0 {
            len += 1;
        }
        let result = PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(
            path, len,
        )));
        CoTaskMemFree(path.cast());
        Ok(result)
    }
}
pub fn install_dir() -> io::Result<PathBuf> {
    Ok(known_folder(&FOLDERID_ProgramFiles)?.join("Portputer Secure Input"))
}
pub fn data_dir() -> io::Result<PathBuf> {
    Ok(known_folder(&FOLDERID_ProgramData)?.join("Portputer Secure Input"))
}
pub fn private_dir() -> io::Result<PathBuf> {
    Ok(data_dir()?.join("Private"))
}
pub fn image_dir() -> io::Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::other("missing image directory"))?
        .into())
}
pub fn process_sid(pid: u32) -> io::Result<String> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut token = std::ptr::null_mut();
        let ok = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        CloseHandle(process);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut size = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
            let mut data = vec![0u64; (size as usize).div_ceil(8)];
            if GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), size, &mut size) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut sid = std::ptr::null_mut();
            if ConvertSidToStringSidW((*data.as_ptr().cast::<TOKEN_USER>()).User.Sid, &mut sid) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut n = 0;
            while *sid.add(n) != 0 {
                n += 1;
            }
            let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid, n));
            LocalFree(sid.cast());
            Ok(value)
        })();
        CloseHandle(token);
        result
    }
}
/// Read-only owner check before trusting the published pipe name.
pub fn system_or_admin_owned(path: &Path) -> io::Result<bool> {
    unsafe {
        let mut owner = std::ptr::null_mut();
        let mut sd = std::ptr::null_mut();
        let mut name = wide(&path.to_string_lossy());
        let error = GetNamedSecurityInfoW(
            name.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        );
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let valid = !owner.is_null()
            && (IsWellKnownSid(owner, WinLocalSystemSid) != 0
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0);
        LocalFree(sd);
        Ok(valid)
    }
}
pub struct Connection {
    runtime: tokio::runtime::Runtime,
    pipe: NamedPipeClient,
}
impl Connection {
    pub fn connect() -> io::Result<Self> {
        let directory = data_dir()?.join("Sessions");
        if !system_or_admin_owned(&directory)? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let path = directory.join(format!("{}.json", session_id()?));
        if !system_or_admin_owned(&path)? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let name = std::fs::read_to_string(path)?;
        if !name.starts_with(r"\\.\pipe\PortputerSecureInput-v2-") || name.len() > 160 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Self::connect_name(&name)
    }
    fn connect_name(name: &str) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let pipe = {
            let _guard = runtime.enter();
            ClientOptions::new()
                .security_qos_flags(0x00100000 | 0x00010000)
                .open(name)?
        };
        // Check SYSTEM ownership, including on test pipes; never send a frame
        // to a squatter. No user image path participates in authorization.
        unsafe {
            let mut owner = std::ptr::null_mut();
            let mut sd = std::ptr::null_mut();
            let error = GetSecurityInfo(
                pipe.as_raw_handle(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            let valid = !owner.is_null() && IsWellKnownSid(owner, WinLocalSystemSid) != 0;
            LocalFree(sd);
            if !valid {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
        Ok(Self { runtime, pipe })
    }
    /// Called by the ordinary app's update integration. The download is opened
    /// with this process's permissions and sent as bounded bytes, never a path.
    pub fn install_update(&mut self, path: &Path, signature: &str) -> io::Result<()> {
        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        self.request(&Request::UpdateBegin {
            size: file.metadata()?.len(),
            signature: signature.into(),
        })?;
        let mut bytes = [0u8; 8192];
        loop {
            let n = file.read(&mut bytes)?;
            if n == 0 {
                break;
            }
            self.request(&Request::UpdateChunk {
                bytes: bytes[..n].to_vec(),
            })?;
        }
        self.request(&Request::UpdateFinish)?;
        Ok(())
    }
    pub fn request(&mut self, request: &Request) -> io::Result<Reply> {
        let bytes = serde_json::to_vec(request)?;
        if bytes.len() > MAX_FRAME * 5 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                self.pipe.write_u32(bytes.len() as u32).await?;
                self.pipe.write_all(&bytes).await?;
                let n = self.pipe.read_u32().await? as usize;
                if n > MAX_FRAME * 5 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let mut frame = vec![0; n];
                self.pipe.read_exact(&mut frame).await?;
                let reply: Reply = serde_json::from_slice(&frame)?;
                if reply.version != VERSION || !reply.ok {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                Ok(reply)
            })
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        })
    }
}
pub struct PipeRelay;
impl Relay for PipeRelay {
    fn connect(&self) -> Result<Box<dyn RelayConnection>, String> {
        Connection::connect()
            .map(|c| Box::new(c) as Box<dyn RelayConnection>)
            .map_err(|_| "Secure-input helper unavailable".into())
    }
}
impl RelayConnection for Connection {
    fn exchange(&mut self, request: RelayRequest) -> Result<RelayReply, String> {
        self.request(&Request::Relay { request })
            .ok()
            .and_then(|r| r.relay)
            .ok_or_else(|| "Secure-input helper unavailable or incompatible".into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_folder_ignores_user_environment() {
        // No global environment mutation: the returned path must be absolute.
        assert!(install_dir().unwrap().is_absolute());
        assert!(data_dir().unwrap().is_absolute());
    }
    #[test]
    fn rejects_user_owned_squatter_on_unique_pipe() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let name = format!(
            r"\\.\pipe\PortputerSecureInput-v2-test-{}",
            hex::encode(random)
        );
        let _pipe = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        assert!(Connection::connect_name(&name).is_err());
    }
}
