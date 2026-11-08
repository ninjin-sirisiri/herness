//! herness desktop binary.
//!
//! Static assets are embedded from `ui/`; there is no Node runtime, sidecar, or
//! bundler. `--smoke-test` starts the real app, waits for the trusted main
//! window, and exits without requiring interaction.

fn main() {
    let smoke_test = std::env::args().any(|argument| argument == "--smoke-test");
    if let Err(error) = herness_desktop::app::run(smoke_test) {
        eprintln!("herness-desktop failed to start: {error}");
        std::process::exit(1);
    }
}
