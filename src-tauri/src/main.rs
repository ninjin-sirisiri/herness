//! herness desktop binary.
//!
//! Static assets are embedded from `ui/`; there is no Node runtime, sidecar, or
//! bundler. `--smoke-test` starts the real app, waits for the trusted main
//! window, and exits without requiring interaction.

fn main() {
    // Controller-only real checks never construct the Tauri app. They are
    // explicit opt-in invocations from the Phase B runbook.
    if let Some(exit_code) = herness_desktop::real_check::main_entry(std::env::args().skip(1)) {
        std::process::exit(exit_code);
    }
    let smoke_test = std::env::args().any(|argument| argument == "--smoke-test");
    let quit_test = std::env::args().any(|argument| argument == "--quit-test");
    let close_reopen_test = std::env::args().any(|argument| argument == "--close-reopen-test");
    if let Err(error) = herness_desktop::app::run(smoke_test, quit_test, close_reopen_test) {
        eprintln!("herness-desktop failed to start: {error}");
        std::process::exit(1);
    }
}
