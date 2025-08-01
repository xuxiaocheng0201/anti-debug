#[cfg(target_os = "windows")]
pub fn is_debugger_present() -> bool {
    let ret = unsafe { windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() };
    ret != 0
}

#[cfg(target_os = "linux")]
pub fn is_debugger_present() -> bool {
    let proc = std::fs::read_to_string("/proc/self/status");
    let Ok(proc) = proc else { return true; };
    let pid = proc.lines().find(|line| line.starts_with("TracerPid:"));
    let Some(pid) = pid else { return true; };
    !pid.ends_with("\t0") && !pid.ends_with(" 0")
}

#[cfg(target_os = "macos")]
pub fn is_debugger_present() -> bool {
    let ret = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    ret == -1
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn is_debugger_present() -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_is_debugger_present() {
        assert!(!super::is_debugger_present());
        assert!(!super::is_debugger_present());
        assert!(!super::is_debugger_present());
    }
}
