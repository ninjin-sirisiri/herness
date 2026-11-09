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
    let mode = match herness_desktop::app::parse_launch_mode(std::env::args().skip(1)) {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("herness-desktop arguments are invalid: {error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = herness_desktop::app::run(mode) {
        eprintln!("herness-desktop failed to start: {error}");
        std::process::exit(1);
    }
}
