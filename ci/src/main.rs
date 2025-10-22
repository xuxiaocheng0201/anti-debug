fn main() {
    let enable = std::env::var("ANTI_DEBUG").is_ok();
    if enable && anti_debug::is_debugger_present().unwrap_or(false) {
        panic!("debugger detected");
    }
}
