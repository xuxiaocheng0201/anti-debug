fn main() {
    let enable = std::env::var("ANTI_DEBUG").is_ok();
    if enable && anti_debug::is_debugger_present() {
        panic!("debugger detected");
    }
}
