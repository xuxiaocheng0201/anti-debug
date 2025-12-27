fn main() {
    let enable = std::env::var("ANTI_DEBUG").is_ok();
    if enable {
        anti_debug::deny_attach().unwrap();
    }
}
