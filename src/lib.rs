pub fn is_debugger_present() -> Result<bool, std::io::Error> {
    #[cfg(target_os = "windows")] {
        // Check with `IsDebuggerPresent`.
        unsafe {
            let result = windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent();
            if result != windows_sys::Win32::Foundation::FALSE {
                return Ok(true);
            }
        }
        // Check with `CheckRemoteDebuggerPresent`.
        #[cfg(feature = "deep-detect")]
        unsafe {
            let mut p_debugger_present = windows_sys::Win32::Foundation::FALSE;
            let result = windows_sys::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                &mut p_debugger_present,
            );
            if result == windows_sys::Win32::Foundation::FALSE {
                return Err(errno::errno().into());
            }
            if p_debugger_present != windows_sys::Win32::Foundation::FALSE {
                return Ok(true);
            }
        }
        // Check with `NtQueryInformationProcess`.
        #[cfg(feature = "deep-detect")]
        unsafe {
            let mut p_debug_port = 0i32;
            let result = windows_sys::Wdk::System::Threading::NtQueryInformationProcess(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                windows_sys::Wdk::System::Threading::ProcessDebugPort,
                &mut p_debug_port as *mut _ as _,
                size_of::<i32>() as _,
                &mut 0,
            );
            let result = windows_sys::Win32::Foundation::RtlNtStatusToDosError(result);
            if result != 0 {
                return Err(errno::Errno(result as _).into());
            }
            if p_debug_port != 0 {
                return Ok(true);
            }
        }
       return Ok(false);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))] {
        // Check with `/proc/self/status`.
        {
            let proc = std::fs::read_to_string("/proc/self/status")?;
            let pid = proc
                .lines()
                .filter_map(|line| line.strip_prefix("TracerPid:"))
                .filter_map(|pid| pid.trim().parse::<i32>().ok())
                .next()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid pid format"))?;
            if pid != 0 {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    #[cfg(target_os = "macos")] {
        // Check with `proc_pidinfo`.
        {
            let pid = std::process::id() as i32;
            let result = libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(pid, 0);
            let proc_bsdinfo = match result {
                Ok(proc_bsdinfo) => proc_bsdinfo,
                Err(_message) => return Err(errno::errno().into()),
            };
            const PROC_FLAG_TRACED: u32 = 2; // use libproc::osx_libproc_bindings::PROC_FLAG_TRACED;
            if proc_bsdinfo.pbi_flags & PROC_FLAG_TRACED != 0 { return Ok(true); }
        }
        return Ok(false);
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
    )))]
    compile_error!("Anti-Debug doesn't support current platform.")
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_is_debugger_present() {
        assert!(!super::is_debugger_present().unwrap_or(false));
        assert!(!super::is_debugger_present().unwrap_or(false));
        assert!(!super::is_debugger_present().unwrap_or(false));
    }
}
