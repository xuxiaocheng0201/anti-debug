#[cfg(all(target_os = "windows", feature = "windows"))]
pub fn is_debugger_present() -> bool {
    let ret = unsafe { windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() };
    ret != 0
}

#[cfg(all(target_os = "linux", feature = "linux"))]
pub fn is_debugger_present() -> bool {
    let proc = std::fs::read_to_string("/proc/self/status");
    let Ok(proc) = proc else { return true; };
    let pid = proc.lines().find(|line| line.starts_with("TracerPid:"));
    let Some(pid) = pid else { return true; };
    !pid.ends_with(" 0")
}

#[cfg(all(target_os = "macos", feature = "macos"))]
pub fn is_debugger_present() -> bool {
    let ret = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    ret == -1
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
