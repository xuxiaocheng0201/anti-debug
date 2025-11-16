#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

/// Checks if a debugger is currently attached to the process.
///
/// This function performs a platform-specific check to detect whether a debugger
/// is actively attached to the current process. This can be useful for implementing
/// anti-debugging techniques or for adjusting behavior when running under a debugger.
///
/// # Platform-specific Behavior
///
/// The implementation varies by platform:
///
/// - **Windows**: Uses the `IsDebuggerPresent` API. When the `deep-detect` feature
///   is enabled, additionally checks `CheckRemoteDebuggerPresent` and
///   `NtQueryInformationProcess` for more comprehensive detection.
/// - **Linux/Android**: Checks the `TracerPid` field in `/proc/self/status`.
/// - **macOS**: Uses the `proc_pidinfo` system call to retrieve process BSD info
///   and checks the `pbi_flags` field.
/// - **Other platforms**: Compilation error.
///
/// # Return Value
///
/// Returns `Ok(true)` if a debugger is detected, `Ok(false)` if no debugger is present,
/// or `Err(std::io::Error)` if the check could not be performed due to a system error.
///
/// This function may return an error in the following situations:
///
/// - Insufficient permissions to access process information
/// - Platform-specific system calls fail
///
/// # Examples
///
/// ```rust
/// # fn main() {
/// match anti_debug::is_debugger_present() {
///     Ok(true) => println!("Debugger detected!"),
///     Ok(false) => println!("No debugger present"),
///     Err(e) => println!("Error checking for debugger: {}", e),
/// }
/// # }
/// ```
///
/// # Notes
///
/// - This detection can be bypassed by skilled attackers using advanced anti-anti-debugging techniques
/// - Some debuggers may not be detected depending on their attachment method
/// - The check is performed at the moment the function is called and may not reflect
///   subsequent attachment/detachment of debuggers
///
/// # Security Considerations
///
/// Do not rely solely on this check for security-critical operations, as determined
/// attackers can bypass debugger detection. This should be used as one component
/// of a comprehensive security strategy.
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
                return Err(std::io::Error::last_os_error());
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
                return Err(std::io::Error::from_raw_os_error(result as _));
            }
            if p_debug_port != 0 {
                return Ok(true);
            }
        }
        Ok(false)
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
        Ok(false)
    }
    #[cfg(target_os = "macos")] {
        // Check with `proc_pidinfo`.
        {
            let pid = std::process::id() as i32;
            let result = libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(pid, 0);
            let proc_bsdinfo = match result {
                Ok(proc_bsdinfo) => proc_bsdinfo,
                Err(_message) => return Err(std::io::Error::last_os_error()),
            };
            const PROC_FLAG_TRACED: u32 = 2; // use libproc::osx_libproc_bindings::PROC_FLAG_TRACED;
            if proc_bsdinfo.pbi_flags & PROC_FLAG_TRACED != 0 { return Ok(true); }
        }
        Ok(false)
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
