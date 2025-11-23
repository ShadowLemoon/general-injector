#![allow(clippy::missing_transmute_annotations)]

use std::ffi::{c_void, CString};
use std::process::ExitCode;

use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessA, CreateRemoteThread, GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOA, WaitForSingleObject,
};
use windows::Win32::UI::Shell::ShellExecuteA;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
use windows::core::{PCSTR, s};

const EXECUTABLES: &[&str] = &[
    "Yuanshen.exe",
    "GenshinImpact.exe",
    "StarRail.exe",
    "ZenlessZoneZero.exe",
    "ZenlessZoneZeroBeta.exe"
];

fn main() -> ExitCode {
    if !is_admin() {
        if run_as_admin() {
            return ExitCode::SUCCESS;
        } else {
            eprintln!("Failed to request admin privileges.");
            let _ = std::io::stdin().read_line(&mut String::new());
            return ExitCode::FAILURE;
        }
    }

    let current_dir = std::env::current_dir().unwrap();

    // 1. 获取上级目录
    let parent_dir = match current_dir.parent() {
        Some(p) => p,
        None => {
            eprintln!("错误: 无法获取上级目录。");
            let _ = std::io::stdin().read_line(&mut String::new());
            return ExitCode::FAILURE;
        }
    };

    // 2. 构建 DLL 的搜索路径 (../plugin/)
    let dll_search_dir = parent_dir.join("plugin");
    if !dll_search_dir.is_dir() {
        eprintln!("Plugin directory not found: {}", dll_search_dir.display());
        let _ = std::io::stdin().read_line(&mut String::new());
        return ExitCode::FAILURE;
    }

    // 3. 搜索唯一的 DLL
    let dlls: Vec<_> = std::fs::read_dir(&dll_search_dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext.eq_ignore_ascii_case("dll")) {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    let dll_path = match dlls.len() {
        0 => {
            eprintln!("No DLL found in plugin directory.");
            let _ = std::io::stdin().read_line(&mut String::new());
            return ExitCode::FAILURE;
        }
        1 => dlls[0].clone(),
        _ => {
            eprintln!("Multiple DLLs found in plugin directory. Please keep only one.");
            for dll in dlls {
                eprintln!(" - {}", dll.display());
            }
            let _ = std::io::stdin().read_line(&mut String::new());
            return ExitCode::FAILURE;
        }
    };

    for &exe_name in EXECUTABLES {
        if current_dir.join(exe_name).is_file() {
            eprintln!("Found game executable: {exe_name}");
            let exe_name = CString::new(exe_name).unwrap();
            let mut proc_info = PROCESS_INFORMATION::default();
            let startup_info = STARTUPINFOA::default();

            unsafe {
                CreateProcessA(
                    PCSTR(exe_name.as_bytes_with_nul().as_ptr()),
                    None,
                    None,
                    None,
                    false,
                    CREATE_SUSPENDED,
                    None,
                    None,
                    &startup_info,
                    &mut proc_info,
                )
                .unwrap();

                if inject_standard(proc_info.hProcess, dll_path.to_str().unwrap()) {
                    ResumeThread(proc_info.hThread);
                }

                CloseHandle(proc_info.hThread).unwrap();
                CloseHandle(proc_info.hProcess).unwrap();
            }

            return ExitCode::SUCCESS;
        }
    }

    eprintln!("can't find game executable in this directory");
    let _ = std::io::stdin().read_line(&mut String::new());

    ExitCode::FAILURE
}

fn inject_standard(h_target: HANDLE, dll_path: &str) -> bool {
    unsafe {
        let loadlib = GetProcAddress(
            GetModuleHandleA(s!("kernel32.dll")).unwrap(),
            s!("LoadLibraryA"),
        )
        .unwrap();

        let dll_path_cstr = CString::new(dll_path).unwrap();
        let dll_path_addr = VirtualAllocEx(
            h_target,
            None,
            dll_path_cstr.to_bytes_with_nul().len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if dll_path_addr.is_null() {
            println!("VirtualAllocEx failed. Last error: {:?}", GetLastError());
            return false;
        }

        WriteProcessMemory(
            h_target,
            dll_path_addr,
            dll_path_cstr.as_ptr() as _,
            dll_path_cstr.to_bytes_with_nul().len(),
            None,
        )
        .unwrap();

        let h_thread = CreateRemoteThread(
            h_target,
            None,
            0,
            Some(std::mem::transmute(loadlib)),
            Some(dll_path_addr),
            0,
            None,
        )
        .unwrap();

        WaitForSingleObject(h_thread, 0xFFFFFFFF);

        VirtualFreeEx(h_target, dll_path_addr, 0, MEM_RELEASE).unwrap();
        CloseHandle(h_thread).unwrap();
        true
    }
}

fn is_admin() -> bool {
    unsafe {
        let mut h_token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0;
        let result = GetTokenInformation(
            h_token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );

        CloseHandle(h_token).ok();

        if result.is_err() {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}

fn run_as_admin() -> bool {
    unsafe {
        let current_exe = std::env::current_exe().unwrap();
        let current_exe_str = CString::new(current_exe.to_str().unwrap()).unwrap();

        let result = ShellExecuteA(
            None,
            s!("runas"),
            PCSTR(current_exe_str.as_ptr() as _),
            None,
            None,
            SW_SHOW,
        );

        (result.0 as isize) > 32
    }
}
