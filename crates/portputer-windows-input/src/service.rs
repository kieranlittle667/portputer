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
            setup::enable()?;
            enroll_ui()?;
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
}
impl Drop for Child {
    fn drop(&mut self) {
        unsafe {
            SetEvent(self.stop);
            if WaitForSingleObject(self.process, 10_000) != WAIT_OBJECT_0 {
                TerminateProcess(self.process, 1);
                WaitForSingleObject(self.process, 5_000);
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
                let mut random = [0; 16];
                getrandom::fill(&mut random).map_err(io::Error::other)?;
                let name = format!(r"Global\PortputerSecureInputStop-{}", hex::encode(random));
                let stop = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide(&name).as_ptr()) };
                if stop.is_null() {
                    continue;
                }
                match spawn_worker(session, &name) {
                    Ok(process) => {
                        children.insert(session, Child { process, stop });
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
            // User tokens are used only to establish the owner, never passed to
            // the broker or retained. Read TOKEN_USER and compare the SID.
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
            if let Some(enrollment) = state.enrollment.as_ref().filter(|e| e.owner == id) {
                if let Some(active) = enrollment
                    .pending
                    .and_then(|id| state.active.get(&id))
                    .filter(|a| !a.auth.trusted())
                {
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
fn enroll_ui() -> Result<()> {
    // This process runs elevated from the protected package. The ordinary
    // application cannot confirm by clicking this high-integrity dialog.
    let mut connection = Connection::connect()?;
    connection.request(&Request::BeginEnrollment)?;
    let until = Instant::now() + Duration::from_secs(secure_input::ENROLL_SECONDS);
    while Instant::now() < until {
        let pending = connection.request(&Request::Pending)?.pending;
        if let Some(pending) = pending {
            let text = format!(
                "Compare this number with the controlling device:\n\n{}\n\nOnly choose Yes if both numbers match. This grants that device access to the lock screen and UAC prompts.",
                pending
                    .comparison
                    .chars()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            let yes = unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    wide(&text).as_ptr(),
                    wide("Portputer: allow device on secure screens").as_ptr(),
                    MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
                )
            } == IDYES;
            if yes {
                connection.request(&Request::Approve { hash: pending.hash })?;
                // Keep this enrollment window's authenticated pipe alive until
                // both confirmations are committed, or the attempt expires.
                while Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(250));
                    if connection.request(&Request::Pending)?.pending.is_none() {
                        return Ok(());
                    }
                }
            }
            let _ = connection.request(&Request::CancelEnrollment);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = connection.request(&Request::CancelEnrollment);
    Err("Enrollment timed out. Start again on both devices.".into())
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
}
