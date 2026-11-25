//! Protected service registration and storage. No copying from the user app.
use crate::win::*;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    io,
    os::windows::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, Instant},
};
use windows_service::{
    service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::*, Security::Authorization::*, Security::*, Storage::FileSystem::*,
};
pub const NAME: &str = "PortputerSecureInput";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn manager() -> Result<ServiceManager> {
    Ok(ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?)
}
fn info(start: ServiceStartType) -> Result<ServiceInfo> {
    Ok(ServiceInfo {
        name: NAME.into(),
        display_name: "Portputer secure-screen input".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: start,
        error_control: ServiceErrorControl::Normal,
        executable_path: image_dir()?.join("portputer-input-service.exe"),
        launch_arguments: vec!["--service".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    })
}
pub fn enabled() -> bool {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .ok()
        .and_then(|m| m.open_service(NAME, ServiceAccess::QUERY_STATUS).ok())
        .is_some_and(|s| {
            s.query_status()
                .is_ok_and(|s| s.current_state == ServiceState::Running)
        })
}
pub fn protect(path: &Path, read_users: bool, system_only: bool) -> io::Result<()> {
    unsafe {
        let sddl = if system_only {
            "D:P(A;OICI;FA;;;SY)"
        } else if read_users {
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"
        } else {
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        };
        let mut sd = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut present = 0;
        let mut dacl = std::ptr::null_mut();
        let mut defaulted = 0;
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
            LocalFree(sd);
            return Err(io::Error::last_os_error());
        }
        let mut name = wide(&path.to_string_lossy());
        let error = SetNamedSecurityInfoW(
            name.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        );
        LocalFree(sd);
        if error != 0 {
            Err(io::Error::from_raw_os_error(error as i32))
        } else {
            Ok(())
        }
    }
}
fn directory(path: &Path, read_users: bool) -> io::Result<()> {
    unsafe {
        let sddl = if read_users {
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"
        } else {
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        };
        let mut sd = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let created = CreateDirectoryW(wide(&path.to_string_lossy()).as_ptr(), &sa);
        let error = GetLastError();
        LocalFree(sd);
        if created == 0 && error != ERROR_ALREADY_EXISTS {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let attributes = GetFileAttributesW(wide(&path.to_string_lossy()).as_ptr());
        if attributes == INVALID_FILE_ATTRIBUTES
            || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !system_or_admin_owned(path)?
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        protect(path, read_users, false)
    }
}
pub fn prepare_store() -> Result<()> {
    directory(&data_dir()?, true)?;
    directory(&data_dir()?.join("Sessions"), true)?;
    directory(&private_dir()?, false)?;
    let key = private_dir()?.join("service.key");
    if !key.exists() {
        let pair = portputer_core::transport::builder().generate_keypair()?;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&key)?;
        file.write_all(&pair.private)?;
        file.sync_all()?;
        protect(&key, false, true)?;
    }
    if std::fs::read(key)?.len() != 32 {
        return Err("invalid protected service identity".into());
    }
    Ok(())
}
fn store<T>(change: impl FnOnce(&mut BTreeSet<String>) -> Result<(T, bool)>) -> Result<T> {
    let until = Instant::now() + Duration::from_secs(2);
    let lock = private_dir()?.join("trusted.lock");
    let _guard = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(&lock)
        {
            Ok(file) => break file,
            Err(e)
                if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32)
                    && Instant::now() < until =>
            {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(e) => return Err(e.into()),
        }
    };
    let path = private_dir()?.join("trusted.json");
    let mut keys = match std::fs::read(&path) {
        Ok(bytes) if bytes.len() <= 8192 => serde_json::from_slice::<BTreeSet<String>>(&bytes)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeSet::new(),
        _ => return Err("invalid protected device list".into()),
    };
    let (value, write) = change(&mut keys)?;
    if write {
        let temp = private_dir()?.join("trusted.new");
        use std::io::Write;
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(&serde_json::to_vec(&keys)?)?;
        file.sync_all()?;
        drop(file);
        if unsafe {
            MoveFileExW(
                wide(&temp.to_string_lossy()).as_ptr(),
                wide(&path.to_string_lossy()).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(value)
}
pub fn trusted(key: &[u8; 32]) -> Result<bool> {
    store(|keys| Ok((keys.contains(&hex::encode(key)), false)))
}
pub fn add_trusted(key: &[u8; 32]) -> Result<()> {
    store(|keys| {
        if keys.len() >= 64 && !keys.contains(&hex::encode(key)) {
            return Err("device limit reached".into());
        }
        keys.insert(hex::encode(key));
        Ok(((), true))
    })
}
pub fn clear_trusted() -> Result<()> {
    if !private_dir()?.is_dir() {
        return Ok(());
    }
    store(|keys| {
        keys.clear();
        Ok(((), true))
    })
}
fn require_packaged() -> Result<()> {
    if image_dir()? != install_dir()? {
        return Err("run the separate per-machine secure-input package".into());
    }
    Ok(())
}
pub fn stop(service: &windows_service::service::Service) -> Result<()> {
    let state = service.query_status()?.current_state;
    if state == ServiceState::Stopped {
        return Ok(());
    }
    if state != ServiceState::StopPending {
        service.stop()?;
    }
    let until = Instant::now() + Duration::from_secs(30);
    while service.query_status()?.current_state != ServiceState::Stopped {
        if Instant::now() >= until {
            return Err("secure-input service did not stop".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
pub fn install() -> Result<()> {
    require_packaged()?;
    protect(&image_dir()?, true, false)?;
    let manager = manager()?;
    let service = match manager.open_service(NAME, ServiceAccess::ALL_ACCESS) {
        Ok(s) => {
            let disabled = s.query_config()?.start_type == ServiceStartType::Disabled;
            stop(&s)?;
            s.change_config(&info(if disabled {
                ServiceStartType::Disabled
            } else {
                ServiceStartType::AutoStart
            })?)?;
            if disabled {
                return Ok(());
            }
            s
        }
        Err(_) => manager.create_service(
            &info(ServiceStartType::AutoStart)?,
            ServiceAccess::ALL_ACCESS,
        )?,
    };
    service.start(&[] as &[OsString])?;
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        match service.query_status()?.current_state {
            ServiceState::Running => return Ok(()),
            ServiceState::Stopped => return Err("secure-input service failed to start".into()),
            _ if Instant::now() >= until => return Err("secure-input startup timed out".into()),
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}
pub fn disable() -> Result<()> {
    require_packaged()?;
    let s = manager()?.open_service(NAME, ServiceAccess::ALL_ACCESS)?;
    stop(&s)?;
    clear_trusted()?;
    s.change_config(&info(ServiceStartType::Disabled)?)?;
    Ok(())
}
pub fn uninstall() -> Result<()> {
    require_packaged()?;
    if let Ok(s) = manager()?.open_service(NAME, ServiceAccess::ALL_ACCESS) {
        stop(&s)?;
        s.delete()?;
    }
    // Only this package's fixed, protected data directory. Refuse junctions.
    let path = data_dir()?;
    if path.exists() {
        let attributes = unsafe { GetFileAttributesW(wide(&path.to_string_lossy()).as_ptr()) };
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !system_or_admin_owned(&path)? {
            return Err("unsafe service data directory".into());
        }
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

pub fn update_directory() -> Result<std::path::PathBuf> {
    let path = private_dir()?.join("Updates");
    directory(&path, false)?;
    Ok(path)
}

pub fn enable() -> Result<()> {
    require_packaged()?;
    let service = manager()?.open_service(NAME, ServiceAccess::ALL_ACCESS)?;
    service.change_config(&info(ServiceStartType::AutoStart)?)?;
    if service.query_status()?.current_state != ServiceState::Running {
        service.start(&[] as &[OsString])?;
    }
    let until = Instant::now() + Duration::from_secs(15);
    while service.query_status()?.current_state != ServiceState::Running {
        if Instant::now() >= until {
            return Err("secure-input startup timed out".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
