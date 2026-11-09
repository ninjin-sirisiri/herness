//! Real, non-privileged WKWebView render evidence.
//!
//! These tests launch the desktop binary in its `--h3-render-test` child-process
//! mode. The child creates a hidden raw WKWebView and writes a versioned
//! manifest plus PNGs. The parent runs a real loopback listener, embeds its
//! address in the candidate, and requires zero received requests.
//!
//! The tests are macOS-only because they exercise the pinned WKWebView bridge.
//! They never construct AppKit in the test process.

#![cfg(target_os = "macos")]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/render");
const RUN_TIMEOUT: Duration = Duration::from_secs(90);

struct LoopbackProbe {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    received_bytes: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl LoopbackProbe {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback probe");
        listener
            .set_nonblocking(true)
            .expect("non-blocking loopback probe");
        let address = listener.local_addr().expect("loopback address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let received_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connection_counter = Arc::clone(&connections);
        let byte_counter = Arc::clone(&received_bytes);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _peer)) => {
                        let recorded = Arc::clone(&recorded);
                        let connections = Arc::clone(&connection_counter);
                        let received_bytes = Arc::clone(&byte_counter);
                        thread::spawn(move || {
                            handle_loopback(stream, recorded, connections, received_bytes)
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            requests,
            connections,
            received_bytes,
            stop,
            thread: Some(thread),
        }
    }

    fn base(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("loopback requests").clone()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn received_bytes(&self) -> usize {
        self.received_bytes.load(Ordering::SeqCst)
    }
}

impl Drop for LoopbackProbe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn handle_loopback(
    mut stream: TcpStream,
    recorded: Arc<Mutex<Vec<String>>>,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    received_bytes: Arc<std::sync::atomic::AtomicUsize>,
) {
    connections.fetch_add(1, Ordering::SeqCst);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buffer = [0u8; 8192];
    let read = stream.read(&mut buffer).unwrap_or(0);
    received_bytes.fetch_add(read, Ordering::SeqCst);
    let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
    let first_line = request.lines().next().unwrap_or_default().to_owned();
    recorded
        .lock()
        .expect("loopback recording")
        .push(first_line);
    let body = b"loopback probe response";
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

struct Fixture {
    _temp: tempfile::TempDir,
    directory: PathBuf,
    html: Vec<u8>,
    css: Vec<u8>,
    svg: Vec<u8>,
}

impl Fixture {
    fn materialise(leak_base: &str) -> Self {
        let temp = tempfile::tempdir().expect("fixture temp dir");
        let directory = temp.path().join("fixture");
        fs::create_dir_all(directory.join("assets")).expect("fixture assets");
        let root = Path::new(FIXTURE_ROOT);
        let template = fs::read_to_string(root.join("candidate.html")).expect("candidate template");
        let html = template.replace("{{LEAK_BASE}}", leak_base).into_bytes();
        let css = fs::read(root.join("candidate.css")).expect("candidate css");
        let svg = fs::read(root.join("assets/diagram.svg")).expect("diagram svg");
        fs::write(directory.join("candidate.html"), &html).expect("write fixture html");
        fs::write(directory.join("candidate.css"), &css).expect("write fixture css");
        fs::write(directory.join("assets/diagram.svg"), &svg).expect("write fixture svg");
        fs::copy(root.join("secret.txt"), directory.join("secret.txt")).expect("write secret");
        fs::copy(root.join("fixture.json"), directory.join("fixture.json"))
            .expect("write fixture json");
        Self {
            _temp: temp,
            directory,
            html,
            css,
            svg,
        }
    }
}

struct ChildRun {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn desktop_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("HERNESS_DESKTOP_BIN") {
        return PathBuf::from(path);
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("target"));
    let binary = target.join("debug/herness-desktop");
    assert!(
        binary.is_file(),
        "desktop binary is missing at {}; run `cargo build -p herness-desktop --locked` first",
        binary.display()
    );
    binary
}

fn run_child(fixture: &Path, output: &Path, extra: &[&str]) -> ChildRun {
    let temp = tempfile::tempdir().expect("child temp dir");
    let app_data = temp.path().join("app-data");
    fs::create_dir_all(&app_data).expect("child app data");
    fs::create_dir_all(output).expect("child output");
    let stdout_path = temp.path().join("stdout.log");
    let stderr_path = temp.path().join("stderr.log");
    let stdout = fs::File::create(&stdout_path).expect("stdout log");
    let stderr = fs::File::create(&stderr_path).expect("stderr log");
    let mut command = Command::new(desktop_binary());
    command
        .arg("--h3-render-test")
        .arg(fixture)
        .arg(output)
        .args(extra)
        .env("HERNESS_APP_DATA_ROOT", &app_data)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let mut child = command.spawn().expect("spawn desktop render child");
    let status = wait_for_child(&mut child, RUN_TIMEOUT);
    let stdout = fs::read_to_string(&stdout_path).unwrap_or_default();
    let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
    ChildRun {
        status,
        stdout,
        stderr,
    }
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll desktop render child") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("desktop render child exceeded {timeout:?}");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_manifest(output: &Path) -> Value {
    let path = output.join("manifest.json");
    let bytes = fs::read(&path).unwrap_or_else(|error| {
        panic!("render manifest is missing at {}: {error}", path.display())
    });
    serde_json::from_slice(&bytes).expect("valid render manifest JSON")
}

fn png_dimensions(bytes: &[u8]) -> (u32, u32) {
    assert!(
        bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "snapshot is not a PNG file"
    );
    assert_eq!(&bytes[12..16], b"IHDR", "PNG does not begin with IHDR");
    let width = u32::from_be_bytes(bytes[16..20].try_into().expect("PNG width"));
    let height = u32::from_be_bytes(bytes[20..24].try_into().expect("PNG height"));
    (width, height)
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("manifest field `{key}` is missing: {value}"))
}

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("manifest field `{key}` is missing: {value}"))
}

fn number(value: &Value, key: &str) -> f64 {
    value
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or_else(|| panic!("manifest field `{key}` is missing: {value}"))
}

#[test]
fn real_hidden_wkwebview_capture_is_complete_and_blocks_every_external_load() {
    let probe = LoopbackProbe::start();
    let fixture = Fixture::materialise(&format!("{}/leaks", probe.base()));
    let output = tempfile::tempdir().expect("evidence output");
    let run = run_child(&fixture.directory, output.path(), &[]);
    let combined = format!("{}\n{}", run.stdout, run.stderr);
    assert!(
        run.status.success(),
        "render child failed with {:?}:\n{combined}",
        run.status
    );
    assert!(
        run.stdout.contains("H3_RENDER_OK"),
        "render child did not report success:\n{combined}"
    );

    let manifest = read_manifest(output.path());
    assert_eq!(
        string(&manifest, "manifestVersion"),
        "h3-render-manifest-v1"
    );
    assert_eq!(string(&manifest, "evidenceSource"), "wkwebview-native");
    assert_eq!(string(&manifest, "status"), "complete");
    assert!(manifest["incompleteReason"].is_null());

    let candidate = &manifest["candidate"];
    assert_eq!(
        string(candidate, "htmlSha256"),
        sha256_hex(&fixture.html),
        "manifest must bind the exact candidate HTML"
    );
    assert_eq!(string(candidate, "cssSha256"), sha256_hex(&fixture.css));
    assert_eq!(
        candidate["resourceCount"].as_u64(),
        Some(1),
        "one declared resource"
    );
    assert_eq!(
        candidate["resources"][0]["sha256"].as_str(),
        Some(sha256_hex(&fixture.svg).as_str())
    );

    let browser = &manifest["browser"];
    let user_agent = string(browser, "userAgent");
    assert!(
        user_agent.contains("AppleWebKit/"),
        "real WebKit user agent expected: {user_agent}"
    );
    assert!(
        string(browser, "webkitVersion")
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
    );
    assert!(!boolean(browser, "tauriIpcInjected"));
    assert!(!boolean(browser, "javaScriptCanOpenWindows"));
    assert_eq!(browser["injectedUserScriptCount"].as_u64(), Some(0));
    assert!(boolean(browser, "contentRuleListCompiled"));
    assert_eq!(browser["contentRuleListRuleCount"].as_u64(), Some(6));
    assert!(
        !browser["contentRuleList"]
            .as_array()
            .expect("content rule list")
            .is_empty()
    );

    let window = &manifest["hiddenWindow"];
    assert!(!boolean(window, "visibleToUser"));
    assert!(boolean(window, "offscreen"));
    assert!(boolean(window, "captureSucceededWhileHidden"));
    assert!(number(window, "originX") <= -10_000.0);
    assert!(!boolean(window, "mainUiWebviewUsed"));

    let isolation = &manifest["isolation"];
    assert!(!boolean(isolation, "renderStorePersistent"));
    assert!(!boolean(isolation, "renderStoreIsDefaultStore"));
    assert!(boolean(isolation, "controlStorePersistent"));
    assert!(boolean(isolation, "mainStoreSeesItsCookie"));
    assert!(boolean(isolation, "renderStoreSeesItsCookie"));
    assert!(boolean(isolation, "mainStoreSeesItsLocalStorage"));
    assert!(boolean(isolation, "renderStoreSeesItsLocalStorage"));
    assert!(!boolean(isolation, "mainCookieVisibleInRender"));
    assert!(!boolean(isolation, "renderCookieVisibleInMain"));
    assert!(!boolean(isolation, "mainLocalStorageVisibleInRender"));
    assert!(!boolean(isolation, "renderLocalStorageVisibleInMain"));

    let configurations = manifest["configurations"]
        .as_array()
        .expect("configuration evidence");
    assert_eq!(configurations.len(), 8, "fixed render matrix");
    let expected = [
        ("desktop-light", 1280, 800, "light", 1.0),
        ("desktop-dark", 1280, 800, "dark", 1.0),
        ("desktop-zoom-200", 1280, 800, "light", 2.0),
        ("desktop-zoom-200-dark", 1280, 800, "dark", 2.0),
        ("mobile-light", 390, 844, "light", 1.0),
        ("mobile-dark", 390, 844, "dark", 1.0),
        ("mobile-zoom-200", 390, 844, "light", 2.0),
        ("mobile-zoom-200-dark", 390, 844, "dark", 2.0),
    ];
    let mut png_digests = Vec::new();
    let mut png_files = Vec::new();
    for (configuration, (id, width, height, appearance, zoom)) in
        configurations.iter().zip(expected)
    {
        assert_eq!(string(configuration, "id"), id);
        assert_eq!(configuration["viewport"]["width"].as_u64(), Some(width));
        assert_eq!(configuration["viewport"]["height"].as_u64(), Some(height));
        assert_eq!(string(configuration, "appearance"), appearance);
        assert_eq!(number(configuration, "pageZoom"), zoom);

        let css_viewport = &configuration["cssViewport"];
        assert!(number(css_viewport, "innerWidth") > 0.0);
        assert!(number(css_viewport, "innerHeight") > 0.0);
        assert!(number(css_viewport, "devicePixelRatio") >= 1.0);

        let dom = &configuration["dom"];
        assert_eq!(string(dom, "scriptVersion"), "h3-render-metrics-v1");
        assert!(
            dom["document"]["elementCount"].as_u64().unwrap_or(0) > 20,
            "{id} should contain a real document"
        );
        assert!(
            dom["document"]["svgElements"].as_u64().unwrap_or(0) > 5,
            "{id} should contain the inline diagram"
        );
        let probe_results = &dom["candidateProbe"];
        assert!(
            probe_results["fetch"]
                .as_str()
                .unwrap_or_default()
                .starts_with("blocked"),
            "{id} page fetch must be blocked, got {probe_results}"
        );
        assert_eq!(
            probe_results["image"].as_str(),
            Some("blocked"),
            "{id} page image must be blocked"
        );

        let accessibility = &configuration["accessibility"];
        assert_eq!(string(accessibility, "source"), "host-js-aria-snapshot-v1");
        assert!(
            accessibility["nodes"]
                .as_array()
                .expect("accessibility nodes")
                .len()
                > 8,
            "{id} accessibility projection is too small"
        );

        let signals = &configuration["signals"];
        assert!(
            signals["ariaNodes"].as_u64().unwrap_or(0) > 8,
            "{id} aria node count"
        );
        assert!(
            signals["headings"].as_u64().unwrap_or(0) >= 4,
            "{id} heading count"
        );
        assert!(
            signals["smallTextElements"].as_u64().unwrap_or(0) >= 1,
            "{id} small text signal"
        );
        assert!(
            number(signals, "minFontSizePx") <= 11.0,
            "{id} minimum font size"
        );

        let protocol = &configuration["protocol"];
        let page_probe = &protocol["pageProbe"];
        let router = &protocol["routerSelfProbe"];
        assert_eq!(string(router, "probeSource"), "in-memory-router");
        assert_eq!(router["unknownJobStatus"].as_u64(), Some(403));
        assert_eq!(router["pathEscapeStatus"].as_u64(), Some(400));
        assert_eq!(router["missingResourceStatus"].as_u64(), Some(404));
        assert_eq!(router["nonCandidateStatus"].as_u64(), Some(404));
        assert!(boolean(protocol, "unknownJobRejected"));
        assert!(boolean(protocol, "missingResourceRejected"));
        assert!(boolean(protocol, "nonCandidateRejected"));
        assert!(
            protocol["navigationsBlocked"].as_u64().unwrap_or(0) >= 1,
            "{id} external navigation was not denied"
        );
        assert_eq!(
            page_probe["candidateProbe"]["popup"].as_str(),
            Some("null"),
            "{id} new window was not denied"
        );
        let ipc = &page_probe["ipc"];
        for field in [
            "tauriInternals",
            "tauriGlobal",
            "ipcGlobal",
            "isTauri",
            "invoke",
        ] {
            assert_eq!(
                string(ipc, field),
                "undefined",
                "{id} exposes {field} to the candidate"
            );
        }
        let requests = protocol["requests"].as_array().expect("protocol requests");
        assert!(
            requests.iter().any(|request| {
                string(request, "path") == "/index.html" && request["status"].as_u64() == Some(200)
            }),
            "{id} must serve the candidate document"
        );

        let png = &configuration["png"];
        let relative = string(png, "path");
        let path = output.path().join(relative);
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("{id} PNG is missing at {}: {error}", path.display()));
        let (pixel_width, pixel_height) = png_dimensions(&bytes);
        assert_eq!(
            png["pixelWidth"].as_u64(),
            Some(u64::from(pixel_width)),
            "{id} manifest width"
        );
        assert_eq!(
            png["pixelHeight"].as_u64(),
            Some(u64::from(pixel_height)),
            "{id} manifest height"
        );
        assert!(
            u64::from(pixel_width) >= width && u64::from(pixel_height) >= height,
            "{id} PNG {pixel_width}x{pixel_height} is smaller than its viewport"
        );
        assert!(bytes.len() > 1_000, "{id} PNG is implausibly small");
        assert_eq!(
            png["sha256"].as_str(),
            Some(sha256_hex(&bytes).as_str()),
            "{id} PNG digest"
        );
        png_digests.push(sha256_hex(&bytes));
        png_files.push(bytes);
    }

    assert_ne!(
        png_digests[0], png_digests[1],
        "light and dark snapshots must differ (native rendering, not a stationary fake)"
    );
    assert_ne!(
        png_digests[0], png_digests[4],
        "desktop and mobile snapshots must differ"
    );
    assert_eq!(
        png_digests
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        png_digests.len(),
        "every configuration must produce a distinct snapshot"
    );
    for bytes in &png_files {
        let _ = png_dimensions(bytes);
    }

    // Mobile configurations must demonstrate the intentional overflow and the
    // overlapping card fixture; the detector is not allowed to always say zero.
    let mobile = &configurations[4];
    assert!(
        mobile["signals"]["overflowingElements"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "mobile overflow signal was not detected"
    );
    assert!(
        mobile["signals"]["overlappingBlocks"].as_u64().unwrap_or(0) >= 1,
        "mobile overlap signal was not detected"
    );

    assert_eq!(
        probe.connections(),
        0,
        "no loopback connection may be opened by the render"
    );
    assert_eq!(
        probe.received_bytes(),
        0,
        "no loopback byte may be sent by the render"
    );
    assert!(
        probe.requests().is_empty(),
        "no loopback request may reach the listener, got {:?}",
        probe.requests()
    );

    // The producer must only read the fixture, never write to it.
    let secret = fs::read(fixture.directory.join("secret.txt")).expect("secret file");
    assert_eq!(
        String::from_utf8_lossy(&secret),
        "SECRET-MUST-NOT-BE-SERVED-BY-THE-RENDER-PROTOCOL\n"
    );
    assert!(!output.path().join("secret.txt").exists());
}

#[test]
fn render_timeout_writes_an_incomplete_manifest_and_never_passes() {
    let probe = LoopbackProbe::start();
    let fixture = Fixture::materialise(&format!("{}/leaks", probe.base()));
    let output = tempfile::tempdir().expect("timeout output");
    let run = run_child(
        &fixture.directory,
        output.path(),
        &["--h3-render-budget-ms", "1"],
    );
    let combined = format!("{}\n{}", run.stdout, run.stderr);
    assert!(
        !run.status.success(),
        "a timed-out render must not exit successfully:\n{combined}"
    );
    assert!(
        run.stdout.contains("H3_RENDER_INCOMPLETE"),
        "child did not report an incomplete render:\n{combined}"
    );
    let manifest = read_manifest(output.path());
    assert_eq!(string(&manifest, "status"), "incomplete");
    let reason = string(&manifest, "incompleteReason");
    assert!(
        reason.starts_with("timeout"),
        "timeout reason expected, got {reason}"
    );
    assert!(
        manifest["configurations"]
            .as_array()
            .expect("configurations")
            .is_empty()
    );
    assert_eq!(
        probe.connections(),
        0,
        "timeout must not connect to the loopback listener"
    );
    assert_eq!(
        probe.received_bytes(),
        0,
        "timeout must not send loopback bytes"
    );
}

#[test]
fn cancellation_writes_an_incomplete_manifest_and_cleans_up() {
    let probe = LoopbackProbe::start();
    let fixture = Fixture::materialise(&format!("{}/leaks", probe.base()));
    let output = tempfile::tempdir().expect("cancel output");
    let run = run_child(
        &fixture.directory,
        output.path(),
        &["--h3-render-cancel-ms", "10"],
    );
    let combined = format!("{}\n{}", run.stdout, run.stderr);
    assert!(
        !run.status.success(),
        "a cancelled render must not exit successfully:\n{combined}"
    );
    assert!(
        run.stdout.contains("H3_RENDER_INCOMPLETE"),
        "child did not report an incomplete render:\n{combined}"
    );
    let manifest = read_manifest(output.path());
    assert_eq!(string(&manifest, "status"), "incomplete");
    let reason = string(&manifest, "incompleteReason");
    assert!(
        reason.starts_with("cancelled"),
        "cancelled reason expected, got {reason}"
    );
    assert_eq!(
        probe.connections(),
        0,
        "cancellation must not connect to the loopback listener"
    );
    assert_eq!(
        probe.received_bytes(),
        0,
        "cancellation must not send loopback bytes"
    );
}
