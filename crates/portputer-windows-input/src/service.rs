use portputer_core::{
    platform::{Injector, windows::WinInjector},
    protocol::SessionKind,
    secure_input::{self, Authorization, Handshake, Payload, RelayReply, RelayRequest},
};
use portputer_windows_input::{Pending, Reply, Request, setup, win::*};
use std::{
    cell::RefCell,
    collections::HashMap,
    ffi::OsString,
    io,
    os::windows::io::AsRawHandle,
    rc::Rc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::Authorization::*,
    Security::*,
    System::{Pipes::*, RemoteDesktop::*, StationsAndDesktops::*, Threading::*},
    UI::{Accessibility::*, WindowsAndMessaging::*},
};
const NAME: &str = "PortputerSecureInput";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn require_system() -> io::Result<()> {
    if process_sid(unsafe { GetCurrentProcessId() })? == "S-1-5-18" {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
pub fn entry() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--install") => setup::install()?,
        Some("--uninstall") => setup::uninstall()?,
        Some("--enroll") => {
            let owner = args
                .windows(2)
                .find(|pair| pair[0] == "--owner")
                .and_then(|pair| pair[1].parse::<usize>().ok())
                .map_or(std::ptr::null_mut(), |value| value as HWND);
            enroll_ui(owner)?;
        }
        Some("--disable") => {
            setup::disable()?;
        }
        Some("--service") => {
            require_system()?;
            service_dispatcher::start(NAME, ffi_service_main)?;
        }
        Some("--worker") => {
            require_system()?;
            worker(
                args.get(2).ok_or("missing parent")?.parse()?,
                args.get(3).ok_or("missing stop event")?,
            )?;
        }
        Some("--apply-update") => {
            require_system()?;
            portputer_windows_input::update::apply_staged()?;
        }
        _ => return Err("unsupported service operation".into()),
    }
    Ok(())
}
define_windows_service!(ffi_service_main, service_main);
fn service_main(_: Vec<OsString>) {
    let _ = run_service();
}
fn status(state: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::SESSION_CHANGE
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(15),
        process_id: None,
    }
}
struct Child {
    process: HANDLE,
    stop: HANDLE,
    discovery: std::path::PathBuf,
}
impl Drop for Child {
    fn drop(&mut self) {
        unsafe {
            SetEvent(self.stop);
            let mut exited = WaitForSingleObject(self.process, 10_000) == WAIT_OBJECT_0;
            if !exited {
                TerminateProcess(self.process, 1);
                exited = WaitForSingleObject(self.process, 5_000) == WAIT_OBJECT_0;
            }
            // Sign-out can terminate a worker before its own cleanup runs.
            // Reap its publication only after confirming that process exited.
            if exited {
                let _ = std::fs::remove_file(&self.discovery);
            }
            CloseHandle(self.stop);
            CloseHandle(self.process);
        }
    }
}
fn run_service() -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = service_control_handler::register(NAME, move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::SessionChange(_) => {
            let _ = tx.send(false);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let result = (|| -> Result<()> {
        setup::prepare_store()?;
        enable_privilege("SeTcbPrivilege")?;
        enable_privilege("SeAssignPrimaryTokenPrivilege")?;
        enable_privilege("SeIncreaseQuotaPrivilege")?;
        handle.set_service_status(status(ServiceState::Running))?;
        let mut children: HashMap<u32, Child> = HashMap::new();
        let mut retries: HashMap<u32, (Instant, u32)> = HashMap::new();
        loop {
            let sessions = owner_sessions();
            children.retain(|session, child| {
                sessions.contains(session)
                    && unsafe { WaitForSingleObject(child.process, 0) } == WAIT_TIMEOUT
            });
            for session in sessions {
                if children.contains_key(&session) {
                    continue;
                }
                let retry = retries.entry(session).or_insert((Instant::now(), 0));
                if Instant::now() < retry.0 {
                    continue;
                }
                retry.1 = (retry.1 + 1).min(6);
                retry.0 = Instant::now() + Duration::from_secs(1 << retry.1);
                let discovery = data_dir()?.join("Sessions").join(format!("{session}.json"));
                let mut random = [0; 16];
                getrandom::fill(&mut random).map_err(io::Error::other)?;
                let name = format!(r"Global\PortputerSecureInputStop-{}", hex::encode(random));
                let stop = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide(&name).as_ptr()) };
                if stop.is_null() {
                    continue;
                }
                match spawn_worker(session, &name) {
                    Ok(process) => {
                        children.insert(
                            session,
                            Child {
                                process,
                                stop,
                                discovery,
                            },
                        );
                    }
                    Err(_) => unsafe {
                        CloseHandle(stop);
                    },
                }
            }
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(true) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                _ => {}
            }
        }
        handle.set_service_status(status(ServiceState::StopPending))?;
        // Signal all workers before waiting; service Stopped means binaries
        // and pipe handles have been released, including on sign-out.
        for child in children.values() {
            unsafe {
                SetEvent(child.stop);
            }
        }
        drop(children);
        Ok(())
    })();
    let mut stopped = status(ServiceState::Stopped);
    if result.is_err() {
        stopped.exit_code = ServiceExitCode::ServiceSpecific(1);
    }
    handle.set_service_status(stopped)?;
    result
}
fn enable_privilege(name: &str) -> io::Result<()> {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut id = std::mem::zeroed();
        let ok = LookupPrivilegeValueW(std::ptr::null(), wide(name).as_ptr(), &mut id);
        if ok == 0 {
            CloseHandle(token);
            return Err(io::Error::last_os_error());
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: id,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        SetLastError(0);
        let ok = AdjustTokenPrivileges(
            token,
            0,
            &privileges,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        let error = GetLastError();
        CloseHandle(token);
        if ok == 0 || error != 0 {
            Err(io::Error::from_raw_os_error(error as i32))
        } else {
            Ok(())
        }
    }
}
fn owner_sessions() -> Vec<u32> {
    unsafe {
        let mut sessions = std::ptr::null_mut();
        let mut count = 0;
        let mut result = vec![];
        if WTSEnumerateSessionsW(std::ptr::null_mut(), 0, 1, &mut sessions, &mut count) == 0 {
            return result;
        }
        for s in std::slice::from_raw_parts(sessions, count as usize) {
            if s.SessionId == 0
                || !(s.State == WTSActive || s.State == WTSConnected || s.State == WTSDisconnected)
            {
                continue;
            }
            let mut token = std::ptr::null_mut();
            if WTSQueryUserToken(s.SessionId, &mut token) == 0 {
                continue;
            }
            // Check that this is a logged-in user session. The token is never
            // passed to the worker or retained.
            let mut size = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
            let mut data = vec![0u64; (size as usize).div_ceil(8)];
            if GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), size, &mut size) != 0
            {
                let user = &*data.as_ptr().cast::<TOKEN_USER>();
                let mut text = std::ptr::null_mut();
                if windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(
                    user.User.Sid,
                    &mut text,
                ) != 0
                {
                    let mut len = 0;
                    while *text.add(len) != 0 {
                        len += 1;
                    }
                    if len > 0 {
                        result.push(s.SessionId);
                    }
                    LocalFree(text.cast());
                }
            }
            CloseHandle(token);
        }
        WTSFreeMemory(sessions.cast());
        result
    }
}
fn spawn_worker(session: u32, stop_name: &str) -> io::Result<HANDLE> {
    unsafe {
        let mut token = std::ptr::null_mut();
        let mut primary = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID,
            &mut token,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let duplicated = DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        );
        CloseHandle(token);
        if duplicated == 0 {
            return Err(io::Error::last_os_error());
        }
        if SetTokenInformation(primary, TokenSessionId, (&session as *const u32).cast(), 4) == 0 {
            CloseHandle(primary);
            return Err(io::Error::last_os_error());
        }
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => {
                CloseHandle(primary);
                return Err(e);
            }
        };
        let mut command = wide(&format!(
            "\"{}\" --worker {} {}",
            exe.display(),
            GetCurrentProcessId(),
            stop_name
        ));
        let mut desktop = wide("winsta0\\default");
        let mut startup: STARTUPINFOW = std::mem::zeroed();
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startup.lpDesktop = desktop.as_mut_ptr();
        let mut child: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessAsUserW(
            primary,
            wide(&exe.to_string_lossy()).as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut child,
        );
        let error = io::Error::last_os_error();
        CloseHandle(primary);
        if ok == 0 {
            Err(error)
        } else {
            CloseHandle(child.hThread);
            Ok(child.hProcess)
        }
    }
}

fn secure_desktop() -> bool {
    unsafe {
        let desktop = OpenInputDesktop(0, 0, DESKTOP_READOBJECTS);
        if desktop.is_null() {
            return false;
        }
        let result = desktop_is_winlogon(desktop);
        CloseDesktop(desktop);
        result
    }
}
fn default_desktop() -> bool {
    unsafe {
        let desktop = OpenInputDesktop(0, 0, DESKTOP_READOBJECTS);
        if desktop.is_null() {
            return false;
        }
        let mut name = [0u16; 128];
        let mut needed = 0;
        let ok = GetUserObjectInformationW(
            desktop,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            256,
            &mut needed,
        ) != 0
            && String::from_utf16_lossy(&name[..name.iter().position(|c| *c == 0).unwrap_or(128)])
                .eq_ignore_ascii_case("Default");
        CloseDesktop(desktop);
        ok
    }
}
unsafe fn desktop_is_winlogon(desktop: HDESK) -> bool {
    unsafe {
        let mut name = [0u16; 128];
        let mut needed = 0;
        GetUserObjectInformationW(
            desktop,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            256,
            &mut needed,
        ) != 0
            && String::from_utf16_lossy(&name[..name.iter().position(|c| *c == 0).unwrap_or(128)])
                .eq_ignore_ascii_case("Winlogon")
    }
}
struct Desktop {
    old: HDESK,
    secure: HDESK,
}
impl Desktop {
    fn enter() -> io::Result<Self> {
        unsafe {
            let secure = OpenInputDesktop(
                0,
                0,
                DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_JOURNALPLAYBACK,
            );
            if secure.is_null() {
                return Err(io::Error::last_os_error());
            }
            if !desktop_is_winlogon(secure) {
                CloseDesktop(secure);
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let old = GetThreadDesktop(GetCurrentThreadId());
            if SetThreadDesktop(secure) == 0 {
                CloseDesktop(secure);
                return Err(io::Error::last_os_error());
            }
            Ok(Self { old, secure })
        }
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        unsafe {
            SetThreadDesktop(self.old);
            CloseDesktop(self.secure);
        }
    }
}
fn elevated_client(pipe: &NamedPipeServer) -> bool {
    // Read the pipe client's effective token for this request, not its path
    // or PID. Revert before any I/O, await or SYSTEM-only operation.
    unsafe {
        if ImpersonateNamedPipeClient(pipe.as_raw_handle()) == 0 {
            return false;
        }
        let mut token = std::ptr::null_mut();
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
        let valid = if opened != 0 {
            let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
            let mut size = 0;
            let elevated = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            ) != 0
                && elevation.TokenIsElevated != 0;
            let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
            let mut n = sid.len() as u32;
            let mut member = 0;
            let admin = CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut n,
            ) != 0
                && CheckTokenMembership(token, sid.as_mut_ptr().cast(), &mut member) != 0
                && member != 0;
            CloseHandle(token);
            elevated && admin
        } else {
            false
        };
        // Failing to revert must never leave the service impersonating a user.
        if RevertToSelf() == 0 {
            std::process::abort();
        }
        valid
    }
}
struct Enrollment {
    owner: u64,
    until: Instant,
    attempts: u32,
    pending: Option<u64>,
}
static DESKTOP_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
unsafe extern "system" fn desktop_changed(
    _: HWINEVENTHOOK,
    _: u32,
    _: HWND,
    _: i32,
    _: i32,
    _: u32,
    _: u32,
) {
    DESKTOP_EPOCH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}
struct DesktopWatcher {
    thread: u32,
    join: Option<std::thread::JoinHandle<()>>,
}
impl DesktopWatcher {
    fn new() -> io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let join = std::thread::spawn(move || unsafe {
            let mut message: MSG = std::mem::zeroed();
            PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_NOREMOVE);
            let hook = SetWinEventHook(
                EVENT_SYSTEM_DESKTOPSWITCH,
                EVENT_SYSTEM_DESKTOPSWITCH,
                std::ptr::null_mut(),
                Some(desktop_changed),
                0,
                0,
                WINEVENT_OUTOFCONTEXT,
            );
            if hook.is_null() {
                let _ = tx.send(None);
                return;
            }
            let _ = tx.send(Some(GetCurrentThreadId()));
            while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            UnhookWinEvent(hook);
        });
        match rx.recv().ok().flatten() {
            Some(thread) => Ok(Self {
                thread,
                join: Some(join),
            }),
            None => {
                let _ = join.join();
                Err(io::Error::other("desktop switch notifications unavailable"))
            }
        }
    }
}
impl Drop for DesktopWatcher {
    fn drop(&mut self) {
        unsafe {
            PostThreadMessageW(self.thread, WM_QUIT, 0, 0);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
struct Active {
    auth: Authorization,
    injector: WinInjector,
    epoch: u64,
    last_input: Instant,
}
struct State {
    enrollment: Option<Enrollment>,
    active: HashMap<u64, Active>,
    next: u64,
    upload: Option<(u64, portputer_windows_input::update::Upload)>,
}
fn create_pipe(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    unsafe {
        // Users can read/write, but cannot create another server instance.
        let mut sd = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)").as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let result = ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(12)
            .create_with_security_attributes_raw(
                name,
                (&mut sa as *mut SECURITY_ATTRIBUTES).cast(),
            );
        LocalFree(sd);
        result
    }
}
fn worker(parent_pid: u32, stop_name: &str) -> io::Result<()> {
    let _desktop_watcher = DesktopWatcher::new()?;
    if process_sid(parent_pid)? != "S-1-5-18" {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let parent = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, parent_pid) };
    let stop = unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide(stop_name).as_ptr()) };
    if parent.is_null() || stop.is_null() {
        unsafe {
            if !parent.is_null() {
                CloseHandle(parent);
            }
            if !stop.is_null() {
                CloseHandle(stop);
            }
        }
        return Err(io::Error::last_os_error());
    }
    let private: [u8; 32] = std::fs::read(private_dir()?.join("service.key"))?
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let name = format!(
        r"\\.\pipe\PortputerSecureInput-v2-{}-{}",
        session_id()?,
        hex::encode(random)
    );
    let discovery = data_dir()?
        .join("Sessions")
        .join(format!("{}.json", session_id()?));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();
    let state = Rc::new(RefCell::new(State {
        enrollment: None,
        active: HashMap::new(),
        next: 1,
        upload: None,
    }));
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let handles = [parent as usize, stop as usize];
    let waiter = std::thread::spawn(move || {
        let handles = handles.map(|h| h as HANDLE);
        unsafe {
            WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE);
        }
        let _ = tx.send(());
    });
    let result=runtime.block_on(local.run_until(async {
        let mut pipe=create_pipe(&name,true)?;
        std::fs::write(&discovery,&name)?;
        let permits=std::sync::Arc::new(tokio::sync::Semaphore::new(secure_input::MAX_SESSIONS));
        loop {
            tokio::select! {
                _=&mut rx=>break,
                connected=pipe.connect()=>{
                    connected?;
                    let connected=pipe;
                    pipe=create_pipe(&name,false)?;
                    if let Ok(permit)=permits.clone().try_acquire_owned() {
                        let state=state.clone();
                        tokio::task::spawn_local(async move {let _permit=permit;let _=serve_pipe(connected,state,private).await;});
                    }
                }
            }
        }
        Ok::<_,io::Error>(())
    }));
    // Dropping LocalSet closes active pipes and releases each session's state.
    drop(local);
    let _ = std::fs::remove_file(discovery);
    for (_, mut active) in state.borrow_mut().active.drain() {
        release(&mut active.injector);
    }
    unsafe {
        SetEvent(stop);
    }
    let _ = waiter.join();
    unsafe {
        CloseHandle(parent);
        CloseHandle(stop);
    }
    result
}
fn release(injector: &mut WinInjector) {
    if let Ok(_desktop) = Desktop::enter() {
        injector.release_all();
    } else {
        injector.discard_held();
    }
}
async fn serve_pipe(
    mut pipe: NamedPipeServer,
    state: Rc<RefCell<State>>,
    private: [u8; 32],
) -> io::Result<()> {
    let id = {
        let mut state = state.borrow_mut();
        let id = state.next;
        state.next += 1;
        id
    };
    let mut handshake: Option<Handshake> = None;
    let mut allow_enroll = false;
    let result = async {
        loop {
            let n = tokio::time::timeout(Duration::from_secs(30), pipe.read_u32())
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?? as usize;
            if n > secure_input::MAX_FRAME * 5 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut bytes = vec![0; n];
            tokio::time::timeout(Duration::from_secs(3), pipe.read_exact(&mut bytes))
                .await
                .map_err(|_| io::ErrorKind::TimedOut)??;
            let request: Request = serde_json::from_slice(&bytes)?;
            let admin = elevated_client(&pipe);
            let reply = handle_request(
                request,
                admin,
                id,
                &state,
                &private,
                &mut handshake,
                &mut allow_enroll,
            )
            .unwrap_or_else(|_| Reply::new(false));
            let ok = reply.ok;
            let bytes = serde_json::to_vec(&reply)?;
            tokio::time::timeout(Duration::from_secs(3), async {
                pipe.write_u32(bytes.len() as u32).await?;
                pipe.write_all(&bytes).await
            })
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
            if !ok {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
    }
    .await;
    let mut state = state.borrow_mut();
    if state.upload.as_ref().is_some_and(|(owner, _)| *owner == id) {
        state.upload = None;
    }
    if let Some(mut active) = state.active.remove(&id) {
        release(&mut active.injector);
    }
    if state.enrollment.as_ref().is_some_and(|e| e.owner == id) {
        state.enrollment = None;
    }
    result
}
fn handle_request(
    request: Request,
    admin: bool,
    id: u64,
    state: &RefCell<State>,
    private: &[u8; 32],
    handshake: &mut Option<Handshake>,
    allow_enroll: &mut bool,
) -> Result<Reply> {
    let mut state = state.borrow_mut();
    if state
        .upload
        .as_ref()
        .is_some_and(|(_, upload)| upload.expired())
    {
        state.upload = None;
    }
    if state
        .enrollment
        .as_ref()
        .is_some_and(|e| Instant::now() >= e.until)
    {
        state.enrollment = None;
    }
    let mut reply = Reply::new(true);
    match request {
        Request::BeginEnrollment if admin => {
            if state.enrollment.is_some() {
                return Err("enrollment already in progress".into());
            }
            state.enrollment = Some(Enrollment {
                owner: id,
                until: Instant::now() + Duration::from_secs(secure_input::ENROLL_SECONDS),
                attempts: 0,
                pending: None,
            });
        }
        Request::Pending if admin => {
            let enrollment = state
                .enrollment
                .as_ref()
                .filter(|e| e.owner == id)
                .ok_or("enrollment expired or cancelled")?;
            if let Some(pending) = enrollment.pending {
                let active = state
                    .active
                    .get(&pending)
                    .ok_or("enrollment connection closed")?;
                if !active.auth.trusted() {
                    reply.pending = Some(Pending {
                        hash: active.auth.channel.hash.clone(),
                        comparison: active.auth.channel.comparison(),
                    });
                }
            }
        }
        Request::Approve { hash } if admin => {
            let pending = state
                .enrollment
                .as_ref()
                .filter(|e| e.owner == id)
                .and_then(|e| e.pending)
                .ok_or("no pending enrollment")?;
            if !state
                .active
                .get_mut(&pending)
                .ok_or("enrollment ended")?
                .auth
                .approve(&hash)
            {
                return Err("enrollment changed".into());
            }
        }
        Request::CancelEnrollment if admin => {
            if state.enrollment.as_ref().is_some_and(|e| e.owner == id) {
                state.enrollment = None;
            }
        }
        Request::Disable if admin => {
            setup::clear_trusted()?;
            state.enrollment = None;
            for (_, mut active) in state.active.drain() {
                release(&mut active.injector);
            }
        }
        Request::UpdateBegin { size, signature } => {
            if state.upload.is_some() {
                return Err("an update upload is already in progress".into());
            }
            state.upload = Some((
                id,
                portputer_windows_input::update::Upload::begin(size, signature)?,
            ));
        }
        Request::UpdateChunk { bytes } => {
            let (_, upload) = state
                .upload
                .as_mut()
                .filter(|(owner, _)| *owner == id)
                .ok_or("no package upload for this connection")?;
            upload.push(&bytes)?;
        }
        Request::UpdateFinish => {
            if !state.upload.as_ref().is_some_and(|(owner, _)| *owner == id) {
                return Err("no package upload for this connection".into());
            }
            let (_, upload) = state.upload.take().unwrap();
            upload.finish()?;
        }
        Request::Relay { request } => {
            let secure = secure_desktop();
            let epoch = DESKTOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst);
            for active in state.active.values_mut() {
                if !secure || active.epoch != epoch {
                    active.injector.discard_held();
                    active.epoch = epoch;
                }
                if active.last_input.elapsed() > Duration::from_secs(30) {
                    release(&mut active.injector);
                    active.last_input = Instant::now();
                }
            }
            let mut frame = None;
            let mut normal_input = None;
            let mut opened = false;
            match request {
                RelayRequest::Open { version, enroll } => {
                    opened = true;
                    if version != secure_input::VERSION {
                        return Err("protocol mismatch".into());
                    }
                    if let Some(mut old) = state.active.remove(&id) {
                        release(&mut old.injector);
                    }
                    *allow_enroll = enroll;
                    if enroll {
                        let e = state
                            .enrollment
                            .as_mut()
                            .ok_or("open the elevated enrollment window first")?;
                        if e.attempts >= 3 || e.pending.is_some() {
                            return Err("enrollment attempt limit".into());
                        }
                        e.attempts += 1;
                    }
                    *handshake = Some(Handshake::new(private, false)?);
                }
                RelayRequest::Frame { frame: incoming } => {
                    if let Some(mut hs) = handshake.take() {
                        hs.read(&incoming)?;
                        if !hs.finished() {
                            frame = Some(hs.write()?);
                            *handshake = Some(hs);
                        } else {
                            let channel = hs.finish()?;
                            let trusted = setup::trusted(&channel.peer)?;
                            if !trusted && !*allow_enroll {
                                return Err("device not enrolled".into());
                            }
                            if *allow_enroll {
                                let e = state.enrollment.as_mut().ok_or("enrollment expired")?;
                                if e.pending.is_some() {
                                    return Err("another enrollment pending".into());
                                }
                                e.pending = Some(id);
                            }
                            // Reenrollment always requires both confirmations, even
                            // if the device key is already in the protected store.
                            let auth = Authorization::new(channel, trusted && !*allow_enroll);
                            state.active.insert(
                                id,
                                Active {
                                    auth,
                                    injector: WinInjector::new(SessionKind::User),
                                    epoch,
                                    last_input: Instant::now(),
                                },
                            );
                        }
                    } else {
                        let active = state.active.get_mut(&id).ok_or("no secure session")?;
                        if let Some(input) = active.auth.receive(&incoming)? {
                            active.last_input = Instant::now();
                            if !setup::trusted(&active.auth.channel.peer)? {
                                return Err("device revoked".into());
                            }
                            let accepted = if let Ok(_desktop) = Desktop::enter() {
                                match input {
                                    secure_input::Input::Key { code, down, repeat } => {
                                        if repeat {
                                            active.injector.repeat(&code)
                                        } else {
                                            active.injector.key(&code, down)
                                        }
                                    }
                                    secure_input::Input::Tap { code, modifiers } => {
                                        active.injector.tap(&code, &modifiers)
                                    }
                                    secure_input::Input::Text { text } => {
                                        active.injector.text(&text);
                                        true
                                    }
                                    secure_input::Input::Release => {
                                        active.injector.release_all();
                                        true
                                    }
                                }
                            } else {
                                active.injector.discard_held();
                                if default_desktop() {
                                    normal_input = Some(input);
                                    true
                                } else {
                                    false
                                }
                            };
                            frame = Some(active.auth.channel.seal(&Payload::Ack { accepted })?);
                        }
                    }
                }
                RelayRequest::Status => {}
            }
            let enrollment_valid = state
                .enrollment
                .as_ref()
                .is_some_and(|e| e.pending == Some(id));
            if let Some(active) = state.active.get_mut(&id) {
                if !active.auth.trusted() && !enrollment_valid {
                    return Err("enrollment ended".into());
                }
                if active.auth.needs_commit() {
                    setup::add_trusted(&active.auth.channel.peer)?;
                    active.auth.committed();
                }
                if frame.is_none() {
                    frame = Some(active.auth.channel.seal(&Payload::Ready {
                        trusted: active.auth.trusted(),
                    })?);
                }
            }
            reply.relay = Some(RelayReply {
                version: secure_input::VERSION,
                secure_desktop: secure,
                opened,
                frame,
                normal_input,
            });
        }
        _ => return Err("administrator confirmation required".into()),
    }
    Ok(reply)
}
// UI and pipe work use separate threads: slow or failed service requests must
// not delay the elevated window, keyboard navigation, painting or cancellation.
enum EnrollmentAction {
    Approve,
    Cancel,
}
enum EnrollmentUpdate {
    Pending(String),
    Approved,
    Complete,
    Failed(String),
}
struct EnrollmentWindow {
    hwnd: HWND,
    _actions: Box<std::sync::mpsc::Sender<EnrollmentAction>>,
}
const ENROLL_APPROVE: usize = 1001;
const ENROLL_MESSAGE: i32 = 1002;
unsafe extern "system" fn enrollment_window_proc(
    hwnd: HWND,
    msg: u32,
    w: WPARAM,
    l: LPARAM,
) -> isize {
    unsafe {
        if msg == WM_INITDIALOG {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, l);
            return 1;
        }
        let actions = GetWindowLongPtrW(hwnd, GWLP_USERDATA)
            as *const std::sync::mpsc::Sender<EnrollmentAction>;
        if msg == WM_CLOSE || (msg == WM_COMMAND && (w & 0xffff) == IDCANCEL as usize) {
            if !actions.is_null() {
                let _ = (*actions).send(EnrollmentAction::Cancel);
            }
            DestroyWindow(hwnd);
            return 1;
        }
        if msg == WM_COMMAND && (w & 0xffff) == ENROLL_APPROVE {
            if !actions.is_null() {
                let _ = (*actions).send(EnrollmentAction::Approve);
            }
            windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow(
                GetDlgItem(hwnd, ENROLL_APPROVE as i32),
                0,
            );
            return 1;
        }
        0
    }
}
// DWORD-aligned standard dialog template with Segoe UI 9-point font.
#[repr(C, align(4))]
struct EnrollmentTemplate {
    header: DLGTEMPLATE,
    menu: u16,
    class: u16,
    title: u16,
    point_size: u16,
    font: [u16; 9],
}
impl EnrollmentWindow {
    fn new(owner: HWND, actions: std::sync::mpsc::Sender<EnrollmentAction>) -> io::Result<Self> {
        unsafe {
            let instance =
                windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null());
            let template = EnrollmentTemplate {
                header: DLGTEMPLATE {
                    style: WS_POPUP
                        | WS_CAPTION
                        | WS_SYSMENU
                        | DS_MODALFRAME as u32
                        | DS_CENTER as u32
                        | DS_SETFONT as u32,
                    dwExtendedStyle: WS_EX_TOPMOST,
                    cdit: 0,
                    x: 0,
                    y: 0,
                    cx: 260,
                    cy: 130,
                },
                menu: 0,
                class: 0,
                title: 0,
                point_size: 9,
                font: [83, 101, 103, 111, 101, 32, 85, 73, 0],
            };
            let mut actions = Box::new(actions);
            let owner = if IsWindow(owner) != 0 {
                owner
            } else {
                std::ptr::null_mut()
            };
            let hwnd = CreateDialogIndirectParamW(
                instance,
                &template.header,
                owner,
                Some(enrollment_window_proc),
                (&mut *actions as *mut std::sync::mpsc::Sender<EnrollmentAction>) as isize,
            );
            if hwnd.is_null() {
                return Err(io::Error::last_os_error());
            }
            SetWindowTextW(hwnd, wide("Portputer: allow secure screens").as_ptr());
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                0,
                0,
                520,
                260,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
            let label = CreateWindowExW(0, wide("STATIC").as_ptr(),
                wide("Starting secure-screen enrollment.\r\nWaiting for the controlling device.\r\nA comparison number will appear here after the handshake.").as_ptr(),
                WS_CHILD | WS_VISIBLE, 20, 20, 470, 135, hwnd, ENROLL_MESSAGE as usize as _, instance, std::ptr::null());
            let approve = CreateWindowExW(
                0,
                wide("BUTTON").as_ptr(),
                wide("Numbers Match").as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
                230,
                175,
                150,
                30,
                hwnd,
                ENROLL_APPROVE as _,
                instance,
                std::ptr::null(),
            );
            let cancel = CreateWindowExW(
                0,
                wide("BUTTON").as_ptr(),
                wide("Cancel").as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
                395,
                175,
                90,
                30,
                hwnd,
                IDCANCEL as usize as _,
                instance,
                std::ptr::null(),
            );
            if label.is_null() || approve.is_null() || cancel.is_null() {
                DestroyWindow(hwnd);
                return Err(io::Error::last_os_error());
            }
            let font = SendMessageW(hwnd, WM_GETFONT, 0, 0);
            for control in [label, approve, cancel] {
                SendMessageW(control, WM_SETFONT, font as usize, 1);
            }
            ShowWindow(hwnd, SW_SHOW);
            windows_sys::Win32::Graphics::Gdi::UpdateWindow(hwnd);
            SetForegroundWindow(hwnd);
            windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus(cancel);
            Ok(Self {
                hwnd,
                _actions: actions,
            })
        }
    }
    fn message(&self, text: &str) {
        unsafe {
            SetWindowTextW(GetDlgItem(self.hwnd, ENROLL_MESSAGE), wide(text).as_ptr());
        }
    }
    fn pending(&self, comparison: &str) {
        self.message(&format!("Compare this number with the controlling device:\r\n\r\n{}\r\n\r\nChoose Numbers Match only if both numbers match. This grants access to the lock screen and UAC prompts.",
            comparison.chars().map(|c| c.to_string()).collect::<Vec<_>>().join(" ")));
        unsafe {
            windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow(
                GetDlgItem(self.hwnd, ENROLL_APPROVE as i32),
                1,
            );
            SetForegroundWindow(self.hwnd);
        }
    }
    fn open(&self) -> bool {
        unsafe {
            let mut message = std::mem::zeroed();
            while PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                if IsDialogMessageW(self.hwnd, &message) == 0 {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
            IsWindow(self.hwnd) != 0
        }
    }
}
impl Drop for EnrollmentWindow {
    fn drop(&mut self) {
        unsafe {
            if IsWindow(self.hwnd) != 0 {
                DestroyWindow(self.hwnd);
            }
        }
        // The callback pointer is valid until DestroyWindow has returned.
    }
}
fn enrollment_requests(
    actions: std::sync::mpsc::Receiver<EnrollmentAction>,
    updates: std::sync::mpsc::Sender<EnrollmentUpdate>,
) -> Result<()> {
    setup::enable()?;
    let mut connection = Connection::connect()?;
    connection.request(&Request::BeginEnrollment)?;
    let until = Instant::now() + Duration::from_secs(secure_input::ENROLL_SECONDS);
    let mut pending: Option<Pending> = None;
    let mut approved = false;
    while Instant::now() < until {
        match actions.recv_timeout(Duration::from_millis(250)) {
            Ok(EnrollmentAction::Cancel) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = connection.request(&Request::CancelEnrollment);
                return Err("Enrollment cancelled.".into());
            }
            Ok(EnrollmentAction::Approve) if !approved => {
                let comparison = pending.as_ref().ok_or("No comparison is ready.")?;
                connection.request(&Request::Approve {
                    hash: comparison.hash.clone(),
                })?;
                approved = true;
                let _ = updates.send(EnrollmentUpdate::Approved);
            }
            _ => {}
        }
        let next = connection.request(&Request::Pending)?.pending;
        if approved && next.is_none() {
            let _ = updates.send(EnrollmentUpdate::Complete);
            return Ok(());
        }
        if let Some(next) = next {
            if pending.as_ref().is_none_or(|old| old.hash != next.hash) {
                if approved {
                    return Err("Enrollment changed. Start again on both devices.".into());
                }
                let _ = updates.send(EnrollmentUpdate::Pending(next.comparison.clone()));
                pending = Some(next);
            }
        }
    }
    let _ = connection.request(&Request::CancelEnrollment);
    Err("Enrollment expired. Start again on both devices.".into())
}
fn enroll_ui(owner: HWND) -> Result<()> {
    let (action_tx, action_rx) = std::sync::mpsc::channel();
    let (update_tx, update_rx) = std::sync::mpsc::channel();
    // Create and paint before any service or pipe calls.
    let window = EnrollmentWindow::new(owner, action_tx.clone())?;
    let worker = std::thread::spawn(move || {
        if let Err(error) = enrollment_requests(action_rx, update_tx.clone()) {
            let _ = update_tx.send(EnrollmentUpdate::Failed(error.to_string()));
        }
    });
    let mut complete = false;
    while window.open() {
        while let Ok(update) = update_rx.try_recv() {
            match update {
                EnrollmentUpdate::Pending(comparison) => window.pending(&comparison),
                EnrollmentUpdate::Approved => window.message("Windows confirmation accepted.\r\nConfirm the same comparison on the controlling device."),
                EnrollmentUpdate::Complete => { complete = true; break; }
                EnrollmentUpdate::Failed(error) => {
                    window.message(&format!("Secure-screen enrollment did not complete.\r\n{}\r\nClose this window and start again on both devices.", error));
                    unsafe {
                        windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow(GetDlgItem(window.hwnd, ENROLL_APPROVE as i32), 0);
                        SetWindowTextW(GetDlgItem(window.hwnd, IDCANCEL), wide("Close").as_ptr());
                    }
                }
            }
        }
        if complete {
            break;
        }
        unsafe {
            MsgWaitForMultipleObjects(0, std::ptr::null(), 0, 50, QS_ALLINPUT);
        }
    }
    let _ = action_tx.send(EnrollmentAction::Cancel);
    let _ = worker.join();
    if complete {
        Ok(())
    } else {
        Err("Enrollment cancelled or failed.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unprivileged_requests_cannot_manage_authorization() {
        let state = RefCell::new(State {
            enrollment: None,
            active: HashMap::new(),
            next: 1,
            upload: None,
        });
        for request in [
            Request::BeginEnrollment,
            Request::Approve { hash: vec![0; 32] },
            Request::Pending,
            Request::CancelEnrollment,
            Request::Disable,
        ] {
            assert!(
                handle_request(request, false, 1, &state, &[0; 32], &mut None, &mut false).is_err()
            );
        }
        assert!(state.borrow().enrollment.is_none());
        assert!(state.borrow().active.is_empty());
    }
    #[test]
    fn update_chunks_require_a_live_upload_owned_by_the_connection() {
        let state = RefCell::new(State {
            enrollment: None,
            active: HashMap::new(),
            next: 1,
            upload: None,
        });
        for request in [
            Request::UpdateChunk { bytes: vec![0] },
            Request::UpdateFinish,
            Request::UpdateBegin {
                size: 0,
                signature: "invalid".into(),
            },
        ] {
            assert!(
                handle_request(request, false, 1, &state, &[0; 32], &mut None, &mut false).is_err()
            );
        }
        assert!(state.borrow().upload.is_none());
    }
    #[test]
    fn enrollment_cannot_open_without_elevated_window() {
        let state = RefCell::new(State {
            enrollment: None,
            active: HashMap::new(),
            next: 1,
            upload: None,
        });
        let request = Request::Relay {
            request: RelayRequest::Open {
                version: secure_input::VERSION,
                enroll: true,
            },
        };
        assert!(
            handle_request(request, false, 2, &state, &[0; 32], &mut None, &mut false).is_err()
        );
    }
    #[test]
    fn confirmation_is_bound_to_elevated_connection_and_expires() {
        let state = RefCell::new(State {
            enrollment: None,
            active: HashMap::new(),
            next: 1,
            upload: None,
        });
        handle_request(
            Request::BeginEnrollment,
            true,
            1,
            &state,
            &[0; 32],
            &mut None,
            &mut false,
        )
        .unwrap();
        assert!(
            handle_request(
                Request::Approve { hash: vec![0; 32] },
                true,
                2,
                &state,
                &[0; 32],
                &mut None,
                &mut false
            )
            .is_err()
        );
        state.borrow_mut().enrollment.as_mut().unwrap().until =
            Instant::now() - Duration::from_secs(1);
        assert!(
            handle_request(
                Request::Approve { hash: vec![0; 32] },
                true,
                1,
                &state,
                &[0; 32],
                &mut None,
                &mut false
            )
            .is_err()
        );
        assert!(state.borrow().enrollment.is_none());
    }
    #[test]
    fn closed_enrollment_cannot_report_successful_completion() {
        let state = RefCell::new(State {
            enrollment: None,
            active: HashMap::new(),
            next: 1,
            upload: None,
        });
        assert!(
            handle_request(
                Request::Pending,
                true,
                1,
                &state,
                &[0; 32],
                &mut None,
                &mut false
            )
            .is_err()
        );
        state.borrow_mut().enrollment = Some(Enrollment {
            owner: 1,
            until: Instant::now() + Duration::from_secs(30),
            attempts: 1,
            pending: Some(2),
        });
        assert!(
            handle_request(
                Request::Pending,
                true,
                1,
                &state,
                &[0; 32],
                &mut None,
                &mut false
            )
            .is_err()
        );
        state.borrow_mut().enrollment.as_mut().unwrap().pending = None;
        assert!(
            handle_request(
                Request::Pending,
                true,
                2,
                &state,
                &[0; 32],
                &mut None,
                &mut false
            )
            .is_err()
        );
        assert!(
            handle_request(
                Request::Pending,
                true,
                1,
                &state,
                &[0; 32],
                &mut None,
                &mut false
            )
            .is_ok()
        );
    }

    #[test]
    #[ignore = "requires an interactive Windows desktop; run on the test VM"]
    fn waiting_dialog_exists_before_handshake_and_accepts_cancel() {
        let (tx, rx) = std::sync::mpsc::channel();
        let window = EnrollmentWindow::new(std::ptr::null_mut(), tx).unwrap();
        unsafe {
            assert_ne!(IsWindowVisible(window.hwnd), 0);
            let mut class = [0u16; 32];
            let len = GetClassNameW(window.hwnd, class.as_mut_ptr(), class.len() as i32);
            assert_eq!(String::from_utf16_lossy(&class[..len as usize]), "#32770");
            assert_eq!(
                windows_sys::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled(GetDlgItem(
                    window.hwnd,
                    ENROLL_APPROVE as i32
                )),
                0
            );
        }
        // No helper connection or controlling device exists in this test.
        let hwnd = window.hwnd as usize;
        let close = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            unsafe {
                PostMessageW(hwnd as HWND, WM_CLOSE, 0, 0);
            }
        });
        let until = Instant::now() + Duration::from_secs(2);
        while window.open() && Instant::now() < until {
            unsafe {
                MsgWaitForMultipleObjects(0, std::ptr::null(), 0, 20, QS_ALLINPUT);
            }
        }
        close.join().unwrap();
        assert_eq!(
            unsafe { IsWindow(window.hwnd) },
            0,
            "waiting dialog must process Cancel without service input"
        );
        assert!(matches!(rx.try_recv(), Ok(EnrollmentAction::Cancel)));
    }
    #[test]
    fn reaping_dead_worker_removes_its_discovery_file() {
        use std::os::windows::process::CommandExt;
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!("portputer-reap-{}", hex::encode(random)));
        std::fs::create_dir(&root).unwrap();
        let discovery = root.join("session.json");
        std::fs::write(&discovery, "stale test publication").unwrap();
        let mut process = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .stdout(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        process.wait().unwrap();
        let mut handle = std::ptr::null_mut();
        unsafe {
            assert_ne!(
                DuplicateHandle(
                    GetCurrentProcess(),
                    process.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut handle,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS
                ),
                0
            );
            let stop = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
            assert!(!stop.is_null());
            drop(Child {
                process: handle,
                stop,
                discovery: discovery.clone(),
            });
        }
        assert!(
            !discovery.exists(),
            "service must clean discovery even when the worker exited abruptly"
        );
        std::fs::remove_dir(root).unwrap();
    }
}
