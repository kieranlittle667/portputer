//! Verify a copied, protected package before executing it as SYSTEM.
//! The package's signed version resource supplies identity and build number;
//! neither an appcast version nor a caller's claimed version is trusted.
use crate::{setup, win::*};
use base64::{Engine, prelude::BASE64_STANDARD};
use ring::signature::{ED25519, UnparsedPublicKey};
use std::{
    io::{self, Write},
    os::windows::{fs::OpenOptionsExt, process::CommandExt},
    path::Path,
};
use windows_sys::Win32::{
    Foundation::*, Security::Authorization::*, Security::*, Storage::FileSystem::*,
    System::Threading::*,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_PACKAGE: u64 = 64 * 1024 * 1024;
const PUBLIC_KEY: &str = include_str!("../../../macos/Support/sparkle-public-key.txt");
const BUILD: &str = match option_env!("PORTPUTER_BUILD_NUMBER") {
    Some(build) => build,
    None => "0",
};
struct UpdateLock(HANDLE);
impl UpdateLock {
    fn acquire(wait: u32) -> Result<Self> {
        unsafe {
            let mut sd = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)").as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let handle = CreateMutexW(
                &sa,
                0,
                wide(r"Global\PortputerSecureInputUpdate-v2").as_ptr(),
            );
            LocalFree(sd);
            if handle.is_null() {
                return Err(io::Error::last_os_error().into());
            }
            let mut owner = std::ptr::null_mut();
            let mut actual = std::ptr::null_mut();
            let error = GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut actual,
            );
            let trusted =
                error == 0 && !owner.is_null() && IsWellKnownSid(owner, WinLocalSystemSid) != 0;
            if !actual.is_null() {
                LocalFree(actual);
            }
            if !trusted {
                CloseHandle(handle);
                return Err("untrusted update lock".into());
            }
            match WaitForSingleObject(handle, wait) {
                WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(handle)),
                _ => {
                    CloseHandle(handle);
                    Err("an update is already in progress".into())
                }
            }
        }
    }
}
impl Drop for UpdateLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
fn verify(bytes: &[u8], signature: &str, key: &str) -> Result<()> {
    let key = BASE64_STANDARD.decode(key.trim())?;
    let signature = BASE64_STANDARD.decode(signature.trim())?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(bytes, &signature)
        .map_err(|_| "invalid secure-input package signature".into())
}
fn package_build(path: &Path) -> Result<u32> {
    unsafe {
        let name = wide(&path.to_string_lossy());
        let mut unused = 0;
        let size = GetFileVersionInfoSizeW(name.as_ptr(), &mut unused);
        if size == 0 || size > 1024 * 1024 {
            return Err("missing package version resource".into());
        }
        let mut bytes = vec![0u64; (size as usize).div_ceil(8)];
        if GetFileVersionInfoW(name.as_ptr(), 0, size, bytes.as_mut_ptr().cast()) == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut info = std::ptr::null_mut();
        let mut len = 0;
        if VerQueryValueW(
            bytes.as_ptr().cast(),
            wide("\\").as_ptr(),
            &mut info,
            &mut len,
        ) == 0
            || len < (std::mem::size_of::<VS_FIXEDFILEINFO>() as u32)
        {
            return Err("invalid package version".into());
        }
        let fixed = &*info.cast::<VS_FIXEDFILEINFO>();
        if fixed.dwSignature != 0xfeef04bd {
            return Err("invalid package version".into());
        }
        let build = fixed.dwFileVersionLS & 0xffff;
        let mut product = std::ptr::null_mut();
        let mut chars = 0;
        if VerQueryValueW(
            bytes.as_ptr().cast(),
            wide(r"\StringFileInfo\040904b0\ProductName").as_ptr(),
            &mut product,
            &mut chars,
        ) == 0
            || chars == 0
            || chars > 128
        {
            return Err("missing package identity".into());
        }
        let product = String::from_utf16_lossy(std::slice::from_raw_parts(
            product.cast::<u16>(),
            chars as usize - 1,
        ));
        if product != "Portputer Secure Input" {
            return Err("this is not a secure-input package".into());
        }
        Ok(build)
    }
}
fn installed_build() -> Result<u32> {
    let running = BUILD.parse::<u32>()?;
    let path = private_dir()?.join("installed-build");
    let saved = match std::fs::read_to_string(path) {
        Ok(s) => s.trim().parse()?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e.into()),
    };
    Ok(running.max(saved))
}
fn newer(candidate: u32, installed: u32) -> Result<()> {
    if candidate > installed {
        Ok(())
    } else {
        Err("secure-input package is not newer than the installed build".into())
    }
}
fn checked_package(path: &Path, signature: &str) -> Result<u32> {
    let bytes = std::fs::read(path)?;
    if bytes.len() as u64 > MAX_PACKAGE {
        return Err("package too large".into());
    }
    verify(&bytes, signature, PUBLIC_KEY)?;
    let build = package_build(path)?;
    newer(build, installed_build()?)?;
    Ok(build)
}
fn upload_parameters(size: u64, signature: &str) -> Result<()> {
    if size == 0 || size > MAX_PACKAGE || signature.len() > 128 {
        return Err("invalid package upload size".into());
    }
    if BASE64_STANDARD.decode(signature.trim())?.len() != 64 {
        return Err("invalid package signature size".into());
    }
    Ok(())
}
/// Package data comes through the pipe. SYSTEM never opens a caller's path.
/// Hold the update lock until a complete protected copy has been verified.
pub struct Upload {
    _lock: UpdateLock,
    file: Option<std::fs::File>,
    directory: std::path::PathBuf,
    expected: u64,
    received: u64,
    expires: std::time::Instant,
    signature: String,
    complete: bool,
}
impl Upload {
    pub fn begin(size: u64, signature: String) -> Result<Self> {
        upload_parameters(size, &signature)?;
        let lock = UpdateLock::acquire(0)?;
        let directory = setup::update_directory()?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .share_mode(0)
            .open(directory.join("package.exe"))?;
        Ok(Self {
            _lock: lock,
            file: Some(file),
            directory,
            expected: size,
            received: 0,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(120),
            signature,
            complete: false,
        })
    }
    pub fn expired(&self) -> bool {
        std::time::Instant::now() > self.expires
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if std::time::Instant::now() > self.expires
            || bytes.is_empty()
            || bytes.len() > crate::MAX_FRAME
            || bytes.len() as u64 > self.expected - self.received
        {
            return Err("invalid package chunk".into());
        }
        self.file
            .as_mut()
            .ok_or("package upload closed")?
            .write_all(bytes)?;
        self.received += bytes.len() as u64;
        Ok(())
    }
    pub fn finish(mut self) -> Result<()> {
        if std::time::Instant::now() > self.expires || self.received != self.expected {
            return Err("incomplete package upload".into());
        }
        let file = self.file.take().ok_or("package upload closed")?;
        file.sync_all()?;
        drop(file);
        let target = self.directory.join("package.exe");
        checked_package(&target, &self.signature)?;
        std::fs::write(self.directory.join("signature"), &self.signature)?;
        let runner = self.directory.join("update-runner.exe");
        std::fs::copy(image_dir()?.join("portputer-input-service.exe"), &runner)?;
        let windows = known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_Windows)?;
        std::process::Command::new(runner)
            .arg("--apply-update")
            .current_dir(&self.directory)
            .env_clear()
            .env("SystemRoot", &windows)
            .env("WINDIR", &windows)
            .env("TEMP", &self.directory)
            .env("TMP", &self.directory)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()?;
        self.complete = true;
        Ok(())
    }
}
impl Drop for Upload {
    fn drop(&mut self) {
        self.file.take();
        if !self.complete {
            let _ = std::fs::remove_file(self.directory.join("package.exe"));
        }
    }
}
pub fn apply_staged() -> Result<()> {
    let _lock = UpdateLock::acquire(10_000)?;
    let directory = setup::update_directory()?;
    let target = directory.join("package.exe");
    let signature = std::fs::read_to_string(directory.join("signature"))?;
    let build = checked_package(&target, &signature)?;
    let status = std::process::Command::new(&target)
        .arg("/S")
        .current_dir(&directory)
        .creation_flags(CREATE_NO_WINDOW)
        .status()?;
    if !status.success() {
        return Err("secure-input installer failed".into());
    }
    std::fs::write(private_dir()?.join("installed-build"), build.to_string())?;
    let _ = std::fs::remove_file(target);
    let _ = std::fs::remove_file(directory.join("signature"));
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the built secure-input installer"]
    fn reads_signed_package_identity_and_build_resource() {
        let path = std::env::var_os("PORTPUTER_TEST_PACKAGE").expect("installer path");
        let build = std::env::var("PORTPUTER_TEST_PACKAGE_BUILD")
            .expect("installer build")
            .parse::<u32>()
            .unwrap();
        assert_eq!(package_build(Path::new(&path)).unwrap(), build);
    }
    #[test]
    fn verifies_signature_and_rejects_tampering() {
        use ring::{
            rand::SystemRandom,
            signature::{Ed25519KeyPair, KeyPair},
        };
        let random = SystemRandom::new();
        let encoded = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap();
        let package = b"secure input package";
        let signature = BASE64_STANDARD.encode(key.sign(package).as_ref());
        let public = BASE64_STANDARD.encode(key.public_key().as_ref());
        assert!(verify(package, &signature, &public).is_ok());
        assert!(verify(b"changed package", &signature, &public).is_err());
        assert!(verify(package, "invalid", &public).is_err());
        assert!(verify(package, &signature, PUBLIC_KEY).is_err());
    }
    #[test]
    fn rejects_downgrades_and_repeated_builds() {
        assert!(newer(54, 53).is_ok());
        assert!(newer(53, 53).is_err());
        assert!(newer(52, 53).is_err());
    }
    #[test]
    fn rejects_invalid_upload_parameters() {
        let signature = BASE64_STANDARD.encode([0u8; 64]);
        assert!(upload_parameters(1, &signature).is_ok());
        assert!(upload_parameters(0, &signature).is_err());
        assert!(upload_parameters(MAX_PACKAGE + 1, &signature).is_err());
        assert!(upload_parameters(1, "invalid").is_err());
    }
}
