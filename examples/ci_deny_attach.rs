fn main() {
    let enable = std::env::var("ANTI_DEBUG").is_ok();
    if enable {
        anti_debug::deny_attach().unwrap();
    }
    if let Ok(debugger) = std::env::var("DEBUGGER") {
        let id = std::process::id();
        let code = match debugger.as_str() {
            "lldb" => std::process::Command::new("lldb")
                .args([
                    "-p", id.to_string().as_str(),
                    "--batch",
                    "-o", "\"detach\"",
                    "-o", "\"quit\"",
                ])
                .spawn().unwrap()
                .wait().unwrap(),
            "gdb" => std::process::Command::new("gdb")
                .args([
                    "-p", id.to_string().as_str(),
                    "--batch",
                    "-ex", "\"detach\"",
                    "-ex", "\"quit\"",
                ])
                .spawn().unwrap()
                .wait().unwrap(),
            _ => panic!("Unknown debugger"),
        };
        assert_eq!(code.success(), std::env::var("DEBUGGER_SUCCESS").is_ok(), "{code}");
    }
}
