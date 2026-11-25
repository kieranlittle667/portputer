//! User-facing opt-in and native elevated helper setup.
use crate::ui;
use windows::{
    Win32::{
        Foundation::{CloseHandle, HWND},
        System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        },
        UI::{
            Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
            WindowsAndMessaging::*,
        },
    },
    core::PCWSTR,
};
pub fn enabled() -> bool {
    portputer_windows_input::setup::enabled()
}
pub fn request(hwnd: HWND, on: bool) -> Result<bool, String> {
    let helper = portputer_windows_input::win::install_dir()
        .map_err(|e| e.to_string())?
        .join("portputer-input-service.exe");
    if !helper.is_file() {
        if !on {
            return Ok(false);
        }
        let files = ui::open_files(hwnd, "Choose the separate Portputer secure-input installer");
        let Some(installer) = files.first() else {
            return Ok(false);
        };
        if installer
            .extension()
            .is_none_or(|e| !e.eq_ignore_ascii_case("exe"))
        {
            return Err("Choose the secure-input installer executable.".into());
        }
        launch(hwnd, installer, "", on)?;
    } else {
        launch(hwnd, &helper, if on { "--enroll" } else { "--disable" }, on)?;
    }
    Ok(true)
}
fn launch(hwnd: HWND, path: &std::path::Path, args: &str, on: bool) -> Result<(), String> {
    let file = ui::wide(&path.to_string_lossy());
    let verb = ui::wide("runas");
    let args = ui::wide(args);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        hwnd,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(args.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    unsafe {
        ShellExecuteExW(&mut info).map_err(|e| e.to_string())?;
    }
    let process = info.hProcess.0 as usize;
    let owner = hwnd.0 as usize;
    let installing = path
        .file_name()
        .is_none_or(|name| !name.eq_ignore_ascii_case("portputer-input-service.exe"));
    std::thread::spawn(move || {
        let handle = windows::Win32::Foundation::HANDLE(process as *mut _);
        let mut code = 1;
        let success = unsafe {
            let done = WaitForSingleObject(handle, 180_000);
            let read = GetExitCodeProcess(handle, &mut code);
            let _ = CloseHandle(handle);
            done.0 == 0 && read.is_ok() && code == 0
        };
        ui::run_on_ui(move || {
            if success && on && installing {
                if let Ok(true) = request(HWND(owner as *mut _), true) {
                    return;
                }
                crate::app::secure_input_finished(on, false);
            } else {
                crate::app::secure_input_finished(on, success);
            }
        });
    });
    Ok(())
}
pub fn wait_for_previous_process() {
    let args: Vec<_> = std::env::args().collect();
    if let Some(pid) = args
        .iter()
        .position(|s| s == "--wait-for-exit")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u32>().ok())
    {
        unsafe {
            if let Ok(process) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
                WaitForSingleObject(process, 15_000);
                let _ = CloseHandle(process);
            }
        }
    }
}
