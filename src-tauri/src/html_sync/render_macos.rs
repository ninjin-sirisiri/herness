//! macOS WKWebView render bridge.
//!
//! This is the only H3 render module that needs `unsafe`: every call into
//! Objective-C must be made with a live `MainThreadMarker`, and the custom
//! protocol handler is an Objective-C object. The allow is deliberately local
//! to this file; the rest of the workspace keeps `unsafe_code = "deny"`.
//!
//! Design constraints enforced here:
//!
//! * The candidate is rendered by a raw `WKWebView` created outside Tauri's
//!   webview builder. No Tauri initialization script is installed, so the page
//!   never sees `window.__TAURI_INTERNALS__`, `window.__TAURI__`, or `ipc`.
//!   Tauri 2.12.5 `manager/webview.rs` installs that bridge unconditionally on
//!   every Tauri webview (non-configurable), so `with_webview` cannot satisfy
//!   the required IPC rejection. The native bridge instead dispatches every
//!   AppKit call through `AppHandle::run_on_main_thread`, which is the same
//!   main-thread hook Tauri uses.
//! * The view uses a non-persistent `WKWebsiteDataStore`, a fresh
//!   `WKProcessPool`, and a job-scoped `h3render://` scheme handler that serves
//!   only in-memory candidate bytes.
//! * A native `WKContentRuleList` blocks http(s), ws(s), ftp(s), and file
//!   loads. Navigation, new windows, downloads, and non-renderable responses
//!   are additionally denied by the native delegates. `on_web_resource_request`
//!   is not used as the network boundary.
//! * The window is borderless, parked outside every screen, ordered in without
//!   activating the application, and never shown to the user.
//! * All WebKit work is dispatched to the AppKit main thread. The calling
//!   worker thread waits with a hard deadline and cooperative cancellation.
#![allow(unsafe_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, ProtocolObject};
use objc2::{
    AllocAnyThread, ClassType, DefinedClass, MainThreadOnly, Message, define_class, msg_send,
};
use objc2_app_kit::{
    NSAppearance, NSAppearanceCustomization, NSAppearanceNameAqua, NSAppearanceNameDarkAqua,
    NSBackingStoreType, NSBitmapImageFileType, NSBitmapImageRep, NSImage, NSWindow,
    NSWindowStyleMask,
};
use objc2_foundation::{
    MainThreadMarker, NSArray, NSData, NSDictionary, NSError, NSHTTPCookie, NSHTTPCookieDomain,
    NSHTTPCookieName, NSHTTPCookiePath, NSHTTPCookiePropertyKey, NSHTTPCookieValue,
    NSHTTPURLResponse, NSMutableArray, NSMutableDictionary, NSObjectProtocol, NSSet, NSString,
    NSURL, NSURLRequest, NSURLRequestCachePolicy,
};
use objc2_web_kit::{
    WKContentRuleList, WKContentRuleListStore, WKContentWorld, WKFrameInfo, WKNavigation,
    WKNavigationAction, WKNavigationActionPolicy, WKNavigationDelegate, WKNavigationResponse,
    WKNavigationResponsePolicy, WKSnapshotConfiguration, WKUIDelegate, WKURLSchemeHandler,
    WKURLSchemeTask, WKUserContentController, WKWebView, WKWebViewConfiguration,
    WKWebpagePreferences, WKWebsiteDataRecord, WKWebsiteDataStore, WKWindowFeatures,
};
use serde_json::Value;
use tauri::AppHandle;

use super::render::{
    BrowserEvidence, CancellationToken, ConfigurationEvidence, CssViewport, HiddenWindowEvidence,
    IsolationEvidence, PngEvidence, ProtocolEvidence, RENDER_CONFIGURATIONS, RENDER_DOCUMENT_PATH,
    RENDER_SCHEME, RenderAppearance, RenderBudget, RenderConfiguration, RenderError,
    RenderEvidence, RenderFailure, RenderJob, RenderManifest, RenderPayload, RenderPng,
    RenderSignals, incomplete_failure,
};
use herness_supervision::ContentDigest;

const CONTENT_RULE_LIST_IDENTIFIER: &str = "herness-h3-render-block-network-v1";

/// Native content rules installed on the render view.
const CONTENT_RULES_JSON: &str = r#"[
  {"trigger":{"url-filter":"^https?://"},"action":{"type":"block"}},
  {"trigger":{"url-filter":"^wss?://"},"action":{"type":"block"}},
  {"trigger":{"url-filter":"^ftps?://"},"action":{"type":"block"}},
  {"trigger":{"url-filter":"^file://"},"action":{"type":"block"}},
  {"trigger":{"url-filter":"^filesystem://"},"action":{"type":"block"}},
  {"trigger":{"url-filter":"^about:"},"action":{"type":"block"}}
]"#;

const METRICS_SCRIPT: &str = include_str!("render_metrics.js");
const ACCESSIBILITY_SCRIPT: &str = include_str!("render_accessibility.js");
const PROTOCOL_PROBE_SCRIPT: &str = include_str!("render_protocol_probe.js");

const WINDOW_X: f64 = -30_000.0;
const WINDOW_Y: f64 = -30_000.0;
const AUX_CONTROL_Y: f64 = -31_000.0;
const AUX_RENDER_Y: f64 = -32_000.0;
const AUX_WIDTH: f64 = 420.0;
const AUX_HEIGHT: f64 = 320.0;
const LOAD_TIMEOUT: Duration = Duration::from_secs(20);
const PREPARE_TIMEOUT: Duration = Duration::from_secs(20);
const SETTLE: Duration = Duration::from_millis(400);
const ISOLATION_ORIGIN: &str = "https://h3-isolation.test/";
const COOKIE_DOMAIN: &str = "h3-isolation.test";
const MAIN_COOKIE: &str = "h3_main_cookie";
const RENDER_COOKIE: &str = "h3_render_cookie";

const CONTROL_SEED_HTML: &str = r#"<!doctype html><html><head><meta charset="utf-8"><title>h3 main store seed</title></head><body><p>main store seed</p><script>
try { localStorage.setItem("h3-main-canary", "main-store"); document.title = "h3-main-seeded"; }
catch (error) { document.title = "h3-main-error:" + (error && error.name); }
</script></body></html>"#;

const RENDER_SEED_HTML: &str = r#"<!doctype html><html><head><meta charset="utf-8"><title>h3 render store seed</title></head><body><p>render store seed</p><script>
try { localStorage.setItem("h3-render-canary", "render-store"); document.title = "h3-render-seeded"; }
catch (error) { document.title = "h3-render-error:" + (error && error.name); }
</script></body></html>"#;

const CONTROL_READ_SCRIPT: &str = r#"JSON.stringify({main: (() => { try { return localStorage.getItem("h3-main-canary"); } catch (e) { return "error:" + e.name; } })(), render: (() => { try { return localStorage.getItem("h3-render-canary"); } catch (e) { return "error:" + e.name; } })()})"#;

const RENDER_READ_SCRIPT: &str = r#"JSON.stringify({main: (() => { try { return localStorage.getItem("h3-main-canary"); } catch (e) { return "error:" + e.name; } })(), render: (() => { try { return localStorage.getItem("h3-render-canary"); } catch (e) { return "error:" + e.name; } })()})"#;

thread_local! {
    static RULE_LIST: RefCell<Option<Retained<WKContentRuleList>>> = RefCell::new(None);
    static SESSIONS: RefCell<BTreeMap<String, RenderSession>> = RefCell::new(BTreeMap::new());
    static AUX_SESSIONS: RefCell<BTreeMap<AuxKind, AuxSession>> = RefCell::new(BTreeMap::new());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AuxKind {
    Control,
    Render,
}

#[derive(Clone, Copy)]
struct Clock {
    started: Instant,
    deadline: Instant,
}

impl Clock {
    fn new(started: Instant, budget: RenderBudget) -> Self {
        Self {
            started,
            deadline: budget.deadline(started),
        }
    }

    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    fn phase_deadline(&self, cap: Duration) -> Instant {
        let now = Instant::now();
        self.deadline.min(now + cap)
    }

    fn check(&self, phase: &str) -> Result<(), RenderError> {
        if Instant::now() >= self.deadline {
            return Err(self.timeout(phase));
        }
        Ok(())
    }

    fn timeout(&self, phase: &str) -> RenderError {
        RenderError::Timeout {
            phase: phase.to_owned(),
            after_ms: self
                .deadline
                .saturating_duration_since(self.started)
                .as_millis() as u64,
        }
    }
}

struct RenderSession {
    window: Retained<NSWindow>,
    webview: Retained<WKWebView>,
    delegate: Retained<RenderDelegate>,
    #[allow(dead_code)]
    scheme: Retained<SchemeHandler>,
    store: Retained<WKWebsiteDataStore>,
    log: Arc<DelegateLog>,
}

struct AuxSession {
    window: Retained<NSWindow>,
    webview: Retained<WKWebView>,
    delegate: Retained<AuxDelegate>,
    store: Retained<WKWebsiteDataStore>,
}

#[derive(Default)]
struct DelegateLog {
    blocked_navigations: Mutex<Vec<String>>,
    blocked_responses: Mutex<Vec<String>>,
    load_errors: Mutex<Vec<String>>,
    new_windows: AtomicUsize,
    downloads: AtomicUsize,
    process_terminations: AtomicUsize,
}

struct RenderDelegateIvars {
    allowed_url: Mutex<String>,
    load_events: Mutex<Option<Sender<Result<(), RenderError>>>>,
    log: Arc<DelegateLog>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[ivars = RenderDelegateIvars]
    struct RenderDelegate;

    unsafe impl NSObjectProtocol for RenderDelegate {}

    unsafe impl WKNavigationDelegate for RenderDelegate {
        #[unsafe(method(webView:decidePolicyForNavigationAction:decisionHandler:))]
        fn decide_policy_for_navigation_action(
            &self,
            _web_view: &WKWebView,
            navigation_action: &WKNavigationAction,
            decision_handler: &block2::Block<dyn Fn(WKNavigationActionPolicy)>,
        ) {
            let url = navigation_url(navigation_action);
            let is_main_frame = unsafe { navigation_action.targetFrame() }
                .map(|frame| unsafe { frame.isMainFrame() })
                .unwrap_or(false);
            let wants_download = navigation_action
                .respondsToSelector(objc2::sel!(shouldPerformDownload))
                && unsafe { navigation_action.shouldPerformDownload() };
            if wants_download {
                self.ivars().log.downloads.fetch_add(1, Ordering::SeqCst);
            }
            let allowed = is_main_frame
                && !wants_download
                && url == *self.ivars().allowed_url.lock().unwrap();
            if !allowed {
                self.ivars()
                    .log
                    .blocked_navigations
                    .lock()
                    .unwrap()
                    .push(url.clone());
            }
            let policy = if allowed {
                WKNavigationActionPolicy::Allow
            } else {
                WKNavigationActionPolicy::Cancel
            };
            decision_handler.call((policy,));
        }

        #[unsafe(method(webView:decidePolicyForNavigationResponse:decisionHandler:))]
        fn decide_policy_for_navigation_response(
            &self,
            _web_view: &WKWebView,
            navigation_response: &WKNavigationResponse,
            decision_handler: &block2::Block<dyn Fn(WKNavigationResponsePolicy)>,
        ) {
            let response = unsafe { navigation_response.response() };
            let scheme = response
                .URL()
                .and_then(|url| url.scheme())
                .map(|scheme| scheme.to_string());
            let can_show = unsafe { navigation_response.canShowMIMEType() };
            if !can_show {
                self.ivars().log.downloads.fetch_add(1, Ordering::SeqCst);
            }
            let allowed = scheme.as_deref() == Some(RENDER_SCHEME) && can_show;
            if !allowed {
                self.ivars()
                    .log
                    .blocked_responses
                    .lock()
                    .unwrap()
                    .push(format!(
                        "{} show={can_show}",
                        response
                            .URL()
                            .and_then(|url| url.absoluteString())
                            .map(|value| value.to_string())
                            .unwrap_or_default()
                    ));
            }
            let policy = if allowed {
                WKNavigationResponsePolicy::Allow
            } else {
                WKNavigationResponsePolicy::Cancel
            };
            decision_handler.call((policy,));
        }

        #[unsafe(method(webView:didFinishNavigation:))]
        fn did_finish_navigation(&self, _web_view: &WKWebView, _navigation: &WKNavigation) {
            take_load_sender(&self.ivars().load_events).map(|sender| sender.send(Ok(())));
        }

        #[unsafe(method(webView:didFailNavigation:withError:))]
        fn did_fail_navigation(
            &self,
            _web_view: &WKWebView,
            _navigation: &WKNavigation,
            error: &NSError,
        ) {
            fail_load(self, error);
        }

        #[unsafe(method(webView:didFailProvisionalNavigation:withError:))]
        fn did_fail_provisional_navigation(
            &self,
            _web_view: &WKWebView,
            _navigation: &WKNavigation,
            error: &NSError,
        ) {
            fail_load(self, error);
        }

        #[unsafe(method(webViewWebContentProcessDidTerminate:))]
        fn web_content_process_did_terminate(&self, _web_view: &WKWebView) {
            self.ivars()
                .log
                .process_terminations
                .fetch_add(1, Ordering::SeqCst);
            if let Some(sender) = take_load_sender(&self.ivars().load_events) {
                let _ = sender.send(Err(RenderError::Native {
                    phase: "load".to_owned(),
                    detail: "web content process terminated".to_owned(),
                }));
            }
        }
    }

    unsafe impl WKUIDelegate for RenderDelegate {
        #[unsafe(method_id(webView:createWebViewWithConfiguration:forNavigationAction:windowFeatures:))]
        unsafe fn create_web_view(
            &self,
            _web_view: &WKWebView,
            _configuration: &WKWebViewConfiguration,
            _navigation_action: &WKNavigationAction,
            _window_features: &WKWindowFeatures,
        ) -> Option<Retained<WKWebView>> {
            self.ivars().log.new_windows.fetch_add(1, Ordering::SeqCst);
            None
        }

        #[unsafe(method(webView:runJavaScriptAlertPanelWithMessage:initiatedByFrame:completionHandler:))]
        unsafe fn run_alert(
            &self,
            _web_view: &WKWebView,
            _message: &NSString,
            _frame: &WKFrameInfo,
            completion_handler: &block2::Block<dyn Fn()>,
        ) {
            completion_handler.call(());
        }

        #[unsafe(method(webView:runJavaScriptConfirmPanelWithMessage:initiatedByFrame:completionHandler:))]
        unsafe fn run_confirm(
            &self,
            _web_view: &WKWebView,
            _message: &NSString,
            _frame: &WKFrameInfo,
            completion_handler: &block2::Block<dyn Fn(objc2::runtime::Bool)>,
        ) {
            completion_handler.call((objc2::runtime::Bool::NO,));
        }

        #[unsafe(method(webView:runJavaScriptTextInputPanelWithPrompt:defaultText:initiatedByFrame:completionHandler:))]
        unsafe fn run_prompt(
            &self,
            _web_view: &WKWebView,
            _prompt: &NSString,
            _default_text: Option<&NSString>,
            _frame: &WKFrameInfo,
            completion_handler: &block2::Block<dyn Fn(*mut NSString)>,
        ) {
            completion_handler.call((std::ptr::null_mut(),));
        }
    }
);

fn navigation_url(action: &WKNavigationAction) -> String {
    unsafe { action.request() }
        .URL()
        .and_then(|url| url.absoluteString())
        .map(|value| value.to_string())
        .unwrap_or_default()
}

fn take_load_sender(
    slot: &Mutex<Option<Sender<Result<(), RenderError>>>>,
) -> Option<Sender<Result<(), RenderError>>> {
    slot.lock().ok().and_then(|mut slot| slot.take())
}

fn fail_load(delegate: &RenderDelegate, error: &NSError) {
    delegate
        .ivars()
        .log
        .load_errors
        .lock()
        .unwrap()
        .push(error.localizedDescription().to_string());
    if let Some(sender) = take_load_sender(&delegate.ivars().load_events) {
        let _ = sender.send(Err(RenderError::Native {
            phase: "load".to_owned(),
            detail: error.localizedDescription().to_string(),
        }));
    }
}

impl RenderDelegate {
    fn new(mtm: MainThreadMarker, allowed_url: String, log: Arc<DelegateLog>) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(RenderDelegateIvars {
            allowed_url: Mutex::new(allowed_url),
            load_events: Mutex::new(None),
            log,
        });
        unsafe { msg_send![super(this), init] }
    }

    fn begin_load(&self, sender: Sender<Result<(), RenderError>>) {
        *self.ivars().load_events.lock().unwrap() = Some(sender);
    }

    fn fail_pending(&self, reason: &str) {
        if let Some(sender) = take_load_sender(&self.ivars().load_events) {
            let _ = sender.send(Err(RenderError::Native {
                phase: "load".to_owned(),
                detail: reason.to_owned(),
            }));
        }
    }
}

struct SchemeHandlerIvars {
    payload: Arc<RenderPayload>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[ivars = SchemeHandlerIvars]
    struct SchemeHandler;

    unsafe impl NSObjectProtocol for SchemeHandler {}

    unsafe impl WKURLSchemeHandler for SchemeHandler {
        #[unsafe(method(webView:startURLSchemeTask:))]
        fn start_url_scheme_task(
            &self,
            _web_view: &WKWebView,
            url_scheme_task: &ProtocolObject<dyn WKURLSchemeTask>,
        ) {
            let request = unsafe { url_scheme_task.request() };
            let Some(url) = request.URL() else {
                fail_scheme_task(url_scheme_task, "request URL is missing");
                return;
            };
            let raw = url
                .absoluteString()
                .map(|value| value.to_string())
                .unwrap_or_default();
            let response = self.ivars().payload.resolve(&raw);
            let status = response.status as isize;
            let headers = NSDictionary::from_slices(
                &[
                    &*NSString::from_str("Content-Type"),
                    &*NSString::from_str("Cache-Control"),
                    &*NSString::from_str("Access-Control-Allow-Origin"),
                ],
                &[
                    &*NSString::from_str(&response.content_type),
                    &*NSString::from_str("no-store"),
                    &*NSString::from_str("*"),
                ],
            );
            let Some(http) = NSHTTPURLResponse::initWithURL_statusCode_HTTPVersion_headerFields(
                NSHTTPURLResponse::alloc(),
                &url,
                status,
                Some(&NSString::from_str("HTTP/1.1")),
                Some(&headers),
            ) else {
                fail_scheme_task(url_scheme_task, "could not build a native response");
                return;
            };
            unsafe {
                url_scheme_task.didReceiveResponse(&http);
                if !response.body.is_empty() {
                    url_scheme_task.didReceiveData(&NSData::with_bytes(&response.body));
                }
                url_scheme_task.didFinish();
            }
        }

        #[unsafe(method(webView:stopURLSchemeTask:))]
        fn stop_url_scheme_task(
            &self,
            _web_view: &WKWebView,
            _url_scheme_task: &ProtocolObject<dyn WKURLSchemeTask>,
        ) {
            // Every response is served synchronously from memory; there is no
            // in-flight work to cancel and no callback may follow a stop.
        }
    }
);

fn fail_scheme_task(task: &ProtocolObject<dyn WKURLSchemeTask>, detail: &str) {
    let error = unsafe {
        NSError::errorWithDomain_code_userInfo(
            &NSString::from_str("dev.herness.h3render"),
            -1,
            None,
        )
    };
    let _ = detail;
    unsafe { task.didFailWithError(&error) };
}

impl SchemeHandler {
    fn new(mtm: MainThreadMarker, payload: Arc<RenderPayload>) -> Retained<Self> {
        let this = mtm
            .alloc::<Self>()
            .set_ivars(SchemeHandlerIvars { payload });
        unsafe { msg_send![super(this), init] }
    }
}

struct AuxDelegateIvars {
    load_events: Mutex<Option<Sender<Result<(), RenderError>>>>,
    log: Arc<DelegateLog>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[ivars = AuxDelegateIvars]
    struct AuxDelegate;

    unsafe impl NSObjectProtocol for AuxDelegate {}

    unsafe impl WKNavigationDelegate for AuxDelegate {
        #[unsafe(method(webView:decidePolicyForNavigationAction:decisionHandler:))]
        fn decide_policy(
            &self,
            _web_view: &WKWebView,
            _navigation_action: &WKNavigationAction,
            decision_handler: &block2::Block<dyn Fn(WKNavigationActionPolicy)>,
        ) {
            // Harness views only ever receive `loadHTMLString`; they have no
            // scheme handler and never load a URL.
            decision_handler.call((WKNavigationActionPolicy::Allow,));
        }

        #[unsafe(method(webView:didFinishNavigation:))]
        fn did_finish(&self, _web_view: &WKWebView, _navigation: &WKNavigation) {
            if let Some(sender) = take_load_sender(&self.ivars().load_events) {
                let _ = sender.send(Ok(()));
            }
        }

        #[unsafe(method(webView:didFailNavigation:withError:))]
        fn did_fail(&self, _web_view: &WKWebView, _navigation: &WKNavigation, error: &NSError) {
            self.fail(error);
        }

        #[unsafe(method(webView:didFailProvisionalNavigation:withError:))]
        fn did_fail_provisional(
            &self,
            _web_view: &WKWebView,
            _navigation: &WKNavigation,
            error: &NSError,
        ) {
            self.fail(error);
        }
    }
);

impl AuxDelegate {
    fn new(mtm: MainThreadMarker, log: Arc<DelegateLog>) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(AuxDelegateIvars {
            load_events: Mutex::new(None),
            log,
        });
        unsafe { msg_send![super(this), init] }
    }

    fn begin_load(&self, sender: Sender<Result<(), RenderError>>) {
        *self.ivars().load_events.lock().unwrap() = Some(sender);
    }

    fn fail_pending(&self, reason: &str) {
        if let Some(sender) = take_load_sender(&self.ivars().load_events) {
            let _ = sender.send(Err(RenderError::Native {
                phase: "isolation_load".to_owned(),
                detail: reason.to_owned(),
            }));
        }
    }

    fn fail(&self, error: &NSError) {
        self.ivars()
            .log
            .load_errors
            .lock()
            .unwrap()
            .push(error.localizedDescription().to_string());
        if let Some(sender) = take_load_sender(&self.ivars().load_events) {
            let _ = sender.send(Err(RenderError::Native {
                phase: "load".to_owned(),
                detail: error.localizedDescription().to_string(),
            }));
        }
    }
}

/// Renders one candidate. Called from a background thread only.
pub(super) fn render(
    app: &AppHandle,
    job: &RenderJob,
    budget: RenderBudget,
    cancellation: &CancellationToken,
) -> Result<RenderEvidence, RenderFailure> {
    let started = Instant::now();
    let clock = Clock::new(started, budget);
    let payload = job.payload();
    let mut manifest = RenderManifest::start(job);
    let mut pngs = Vec::new();

    let outcome = render_inner(
        app,
        job,
        &payload,
        clock,
        cancellation,
        &mut manifest,
        &mut pngs,
    );
    let teardown = teardown(app, job.job_id());

    manifest.hidden_window.ordered_out = teardown.is_ok();
    manifest.hidden_window.capture_succeeded_while_hidden = !pngs.is_empty();

    match (outcome, teardown) {
        (Ok(()), Ok(())) => {
            manifest.finish(started);
            let evidence = RenderEvidence { manifest, pngs };
            if let Err(error) = evidence.validate() {
                return Err(incomplete_failure(
                    started,
                    error,
                    evidence.manifest,
                    evidence.pngs,
                ));
            }
            Ok(evidence)
        }
        (Ok(()), Err(error)) => Err(incomplete_failure(started, error, manifest, pngs)),
        (Err(error), _) => Err(incomplete_failure(started, error, manifest, pngs)),
    }
}

fn render_inner(
    app: &AppHandle,
    job: &RenderJob,
    payload: &Arc<RenderPayload>,
    clock: Clock,
    cancellation: &CancellationToken,
    manifest: &mut RenderManifest,
    pngs: &mut Vec<RenderPng>,
) -> Result<(), RenderError> {
    clock.check("start")?;
    check_cancel(cancellation)?;
    prepare(app, job.job_id(), Arc::clone(payload), clock, cancellation)?;

    let mut browser_set = false;
    let mut hidden: Option<WindowSnapshot> = None;
    let mut previous_blocked = BlockCounts::default();

    for configuration in RENDER_CONFIGURATIONS {
        clock.check(configuration.id)?;
        check_cancel(cancellation)?;
        let configuration_started = Instant::now();

        let window = configure(app, job.job_id(), configuration, clock, cancellation)?;
        hidden = Some(window);

        let log_before = payload.protocol_log().len();
        load(app, job.job_id(), clock, cancellation)?;
        settle(clock, cancellation)?;

        let metrics = async_main(
            app,
            clock_with(clock, Duration::from_secs(10)),
            cancellation,
            "dom",
            {
                let job_id = job.job_id().to_owned();
                move |mtm, sender| {
                    start_evaluate_on_main(mtm, &job_id, METRICS_SCRIPT, false, sender)
                }
            },
        )?;
        let accessibility = async_main(
            app,
            clock_with(clock, Duration::from_secs(10)),
            cancellation,
            "accessibility",
            {
                let job_id = job.job_id().to_owned();
                move |mtm, sender| {
                    start_evaluate_on_main(mtm, &job_id, ACCESSIBILITY_SCRIPT, false, sender)
                }
            },
        )?;
        let probe = async_main(
            app,
            clock_with(clock, Duration::from_secs(10)),
            cancellation,
            "protocol_probe",
            {
                let job_id = job.job_id().to_owned();
                move |mtm, sender| {
                    start_evaluate_on_main(mtm, &job_id, PROTOCOL_PROBE_SCRIPT, true, sender)
                }
            },
        )?;

        verify_ipc(&probe)?;
        verify_protocol(&probe, payload)?;

        let png = async_main(
            app,
            clock_with(clock, Duration::from_secs(10)),
            cancellation,
            "snapshot",
            {
                let job_id = job.job_id().to_owned();
                move |mtm, sender| start_snapshot_on_main(mtm, &job_id, sender)
            },
        )?;

        let mut dom: Value = parse_json(&metrics, "dom metrics")?;
        let accessibility: Value = parse_json(&accessibility, "accessibility projection")?;
        let probe: Value = parse_json(&probe, "protocol probe")?;
        // Candidate scripts run in the page world; the metrics script runs in
        // an isolated content world and therefore cannot see page globals. The
        // page-world protocol probe carries them over explicitly.
        if let Some(candidate_probe) = probe.get("candidateProbe") {
            dom["candidateProbe"] = candidate_probe.clone();
        }
        let css_viewport = css_viewport(&dom)?;
        let signals = RenderSignals::from_evidence(&dom, &accessibility)?;
        if signals.aria_nodes == 0 || signals.headings == 0 {
            return Err(RenderError::IncompleteCapture {
                detail: format!(
                    "{} produced an empty accessibility projection",
                    configuration.id
                ),
            });
        }

        if !browser_set {
            manifest.browser = browser_evidence(&dom)?;
            browser_set = true;
        }

        let png_path = format!("{}.png", configuration.id);
        let png_evidence = PngEvidence {
            path: png_path.clone(),
            pixel_width: png.1,
            pixel_height: png.2,
            bytes: png.0.len() as u64,
            sha256: ContentDigest::sha256(&png.0),
        };
        pngs.push(RenderPng::new(png_path, png.0, png.1, png.2));

        let cumulative_blocked = block_counts(
            app,
            job.job_id(),
            clock_with(clock, Duration::from_secs(5)),
            cancellation,
        )?;
        let blocked = cumulative_blocked.delta(previous_blocked);
        previous_blocked = cumulative_blocked;
        let all_log = payload.protocol_log();
        let new_records = all_log.get(log_before..).unwrap_or(&[]).to_vec();
        let protocol = ProtocolEvidence {
            unknown_job_rejected: all_log.iter().any(|record| record.reason == "unknown_job"),
            path_escape_rejected: all_log
                .iter()
                .any(|record| record.reason == "path_escape" || record.reason == "invalid_url"),
            missing_resource_rejected: all_log
                .iter()
                .any(|record| record.reason == "missing_resource"),
            non_candidate_rejected: all_log
                .iter()
                .any(|record| record.reason == "missing_resource" && record.url.contains("secret")),
            new_windows_blocked: blocked.new_windows,
            downloads_blocked: blocked.downloads,
            navigations_blocked: blocked.navigations,
            responses_blocked: blocked.responses,
            requests: new_records,
            page_probe: probe,
            router_self_probe: payload.router_self_probe(),
        };
        verify_protocol_evidence(&protocol)?;

        manifest.push(ConfigurationEvidence {
            id: configuration.id.to_owned(),
            viewport: configuration.viewport,
            appearance: configuration.appearance,
            page_zoom: configuration.page_zoom,
            css_viewport,
            png: png_evidence,
            dom,
            accessibility,
            signals,
            protocol,
            timing_ms: configuration_started.elapsed().as_millis() as u64,
        });
    }

    let isolation = isolation::run(app, job.job_id(), clock, cancellation)?;
    if !isolation.is_isolated() {
        return Err(RenderError::IncompleteCapture {
            detail: "render and default website data stores were not isolated".to_owned(),
        });
    }
    manifest.isolation = isolation;

    let Some(hidden) = hidden else {
        return Err(RenderError::IncompleteCapture {
            detail: "no hidden render window was created".to_owned(),
        });
    };
    if !hidden.offscreen {
        return Err(RenderError::IncompleteCapture {
            detail: "render window was not parked outside every screen".to_owned(),
        });
    }
    manifest.hidden_window = HiddenWindowEvidence {
        visible_to_user: false,
        offscreen: true,
        origin_x: hidden.origin_x,
        origin_y: hidden.origin_y,
        alpha: hidden.alpha,
        ordered_front: hidden.ordered_front,
        ordered_out: false,
        capture_succeeded_while_hidden: !pngs.is_empty(),
        main_ui_webview_used: false,
    };
    Ok(())
}

#[derive(Clone, Copy)]
struct WindowSnapshot {
    origin_x: f64,
    origin_y: f64,
    alpha: f64,
    offscreen: bool,
    ordered_front: bool,
}

fn check_cancel(cancellation: &CancellationToken) -> Result<(), RenderError> {
    if cancellation.is_cancelled() {
        return Err(RenderError::Cancelled {
            reason: cancellation
                .reason()
                .unwrap_or_else(|| "cancelled by caller".to_owned()),
        });
    }
    Ok(())
}

fn prepare(
    app: &AppHandle,
    job_id: &str,
    payload: Arc<RenderPayload>,
    clock: Clock,
    cancellation: &CancellationToken,
) -> Result<(), RenderError> {
    let job_id = job_id.to_owned();
    async_main(
        app,
        clock_with(clock, PREPARE_TIMEOUT),
        cancellation,
        "prepare",
        move |mtm, sender| prepare_on_main(mtm, &job_id, payload, sender),
    )
}

fn clock_with(clock: Clock, cap: Duration) -> Clock {
    Clock {
        started: clock.started,
        deadline: clock.phase_deadline(cap),
    }
}

fn prepare_on_main(
    mtm: MainThreadMarker,
    job_id: &str,
    payload: Arc<RenderPayload>,
    sender: Sender<Result<(), RenderError>>,
) -> Result<(), RenderError> {
    let cached = RULE_LIST.with(|cell| cell.borrow().clone());
    if let Some(rules) = cached {
        let result = create_session(mtm, job_id, payload, &rules).map(|_| ());
        let _ = sender.send(result);
        return Ok(());
    }

    let Some(store) = (unsafe { WKContentRuleListStore::defaultStore(mtm) }) else {
        let _ = sender.send(Err(RenderError::Native {
            phase: "content_rule_list".to_owned(),
            detail: "WKContentRuleListStore.defaultStore returned nil".to_owned(),
        }));
        return Ok(());
    };
    let identifier = NSString::from_str(CONTENT_RULE_LIST_IDENTIFIER);
    let rules_json = NSString::from_str(CONTENT_RULES_JSON);
    let job_id = job_id.to_owned();
    let block = RcBlock::new(move |list: *mut WKContentRuleList, error: *mut NSError| {
        let result = (|| -> Result<(), RenderError> {
            if list.is_null() {
                let detail = if error.is_null() {
                    "content rule list compilation returned nil".to_owned()
                } else {
                    unsafe { (&*error).localizedDescription().to_string() }
                };
                return Err(RenderError::Native {
                    phase: "content_rule_list".to_owned(),
                    detail,
                });
            }
            let rules = unsafe { Retained::retain(list) }.ok_or_else(|| RenderError::Native {
                phase: "content_rule_list".to_owned(),
                detail: "could not retain the compiled content rule list".to_owned(),
            })?;
            RULE_LIST.with(|cell| *cell.borrow_mut() = Some(rules.clone()));
            let mtm = MainThreadMarker::new().ok_or_else(|| RenderError::Native {
                phase: "content_rule_list".to_owned(),
                detail: "content rule list callback was not delivered on the main thread"
                    .to_owned(),
            })?;
            create_session(mtm, &job_id, Arc::clone(&payload), &rules).map(|_| ())
        })();
        let _ = sender.send(result);
    });
    unsafe {
        store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler(
            Some(&identifier),
            Some(&rules_json),
            Some(&block),
        );
    }
    Ok(())
}

fn create_session(
    mtm: MainThreadMarker,
    job_id: &str,
    payload: Arc<RenderPayload>,
    rules: &WKContentRuleList,
) -> Result<(), RenderError> {
    let first = RENDER_CONFIGURATIONS[0];
    let window = unsafe {
        NSWindow::initWithContentRect_styleMask_backing_defer(
            mtm.alloc::<NSWindow>(),
            objc2_foundation::NSRect::new(
                objc2_foundation::NSPoint::new(WINDOW_X, WINDOW_Y),
                objc2_foundation::NSSize::new(
                    f64::from(first.viewport.width),
                    f64::from(first.viewport.height),
                ),
            ),
            NSWindowStyleMask::Borderless,
            NSBackingStoreType::Buffered,
            false,
        )
    };
    unsafe { window.setReleasedWhenClosed(false) };
    window.setOpaque(true);
    window.setAlphaValue(1.0);
    window.setIgnoresMouseEvents(true);
    window.setCanHide(false);
    window.setHidesOnDeactivate(false);

    let configuration = unsafe { WKWebViewConfiguration::new(mtm) };
    let store = unsafe { WKWebsiteDataStore::nonPersistentDataStore(mtm) };
    unsafe {
        let preferences: Retained<objc2_web_kit::WKPreferences> = configuration.preferences();
        preferences.setJavaScriptCanOpenWindowsAutomatically(false);
        let page_preferences: Retained<WKWebpagePreferences> =
            configuration.defaultWebpagePreferences();
        page_preferences.setAllowsContentJavaScript(true);
        configuration.setWebsiteDataStore(&store);
    }
    let controller: Retained<WKUserContentController> =
        unsafe { configuration.userContentController() };
    unsafe { controller.addContentRuleList(rules) };

    let scheme = SchemeHandler::new(mtm, Arc::clone(&payload));
    let scheme_protocol = ProtocolObject::from_ref(&*scheme);
    unsafe {
        configuration.setURLSchemeHandler_forURLScheme(
            Some(scheme_protocol),
            &NSString::from_str(RENDER_SCHEME),
        );
    }

    let frame = objc2_foundation::NSRect::new(
        objc2_foundation::NSPoint::new(0.0, 0.0),
        objc2_foundation::NSSize::new(
            f64::from(first.viewport.width),
            f64::from(first.viewport.height),
        ),
    );
    let webview = unsafe {
        WKWebView::initWithFrame_configuration(mtm.alloc::<WKWebView>(), frame, &configuration)
    };
    let allowed = format!("{RENDER_SCHEME}://{job_id}/{RENDER_DOCUMENT_PATH}");
    let log = Arc::new(DelegateLog::default());
    let delegate = RenderDelegate::new(mtm, allowed, Arc::clone(&log));
    unsafe {
        webview.setNavigationDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        webview.setUIDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    }
    window.setContentView(Some(webview.as_super()));
    window.orderFrontRegardless();

    SESSIONS.with(|sessions| {
        sessions.borrow_mut().insert(
            job_id.to_owned(),
            RenderSession {
                window,
                webview,
                delegate,
                scheme,
                store,
                log,
            },
        );
    });
    Ok(())
}

fn configure(
    app: &AppHandle,
    job_id: &str,
    configuration: RenderConfiguration,
    clock: Clock,
    cancellation: &CancellationToken,
) -> Result<WindowSnapshot, RenderError> {
    let job_id = job_id.to_owned();
    async_main(
        app,
        clock,
        cancellation,
        "configure",
        move |_mtm, sender| {
            let result = (|| -> Result<WindowSnapshot, RenderError> {
                let Some((window, webview)) = SESSIONS.with(|sessions| {
                    sessions
                        .borrow()
                        .get(&job_id)
                        .map(|session| (session.window.clone(), session.webview.clone()))
                }) else {
                    return Err(missing_session(&job_id));
                };
                let size = objc2_foundation::NSSize::new(
                    f64::from(configuration.viewport.width),
                    f64::from(configuration.viewport.height),
                );
                window.setContentSize(size);
                webview.setFrame(objc2_foundation::NSRect::new(
                    objc2_foundation::NSPoint::new(0.0, 0.0),
                    size,
                ));
                let appearance = unsafe {
                    NSAppearance::appearanceNamed(match configuration.appearance {
                        RenderAppearance::Light => NSAppearanceNameAqua,
                        RenderAppearance::Dark => NSAppearanceNameDarkAqua,
                    })
                };
                window.setAppearance(appearance.as_deref());
                webview.setAppearance(appearance.as_deref());
                unsafe { webview.setPageZoom(configuration.page_zoom) };
                let frame = window.frame();
                Ok(WindowSnapshot {
                    origin_x: frame.origin.x,
                    origin_y: frame.origin.y,
                    alpha: window.alphaValue(),
                    offscreen: frame.origin.x <= -10_000.0 || frame.origin.y <= -10_000.0,
                    ordered_front: window.isVisible(),
                })
            })();
            let _ = sender.send(result);
            Ok(())
        },
    )
}

fn missing_session(job_id: &str) -> RenderError {
    RenderError::Native {
        phase: "session".to_owned(),
        detail: format!("render session `{job_id}` is not present on the main thread"),
    }
}

fn load(
    app: &AppHandle,
    job_id: &str,
    clock: Clock,
    cancellation: &CancellationToken,
) -> Result<(), RenderError> {
    let job_id = job_id.to_owned();
    let (load_tx, load_rx) = mpsc::channel();
    let load_tx_for_main = load_tx.clone();
    let clock = clock_with(clock, LOAD_TIMEOUT);
    dispatch(app, clock, "load", move |mtm| {
        if let Err(error) = start_load_on_main(mtm, &job_id, load_tx_for_main.clone()) {
            let _ = load_tx_for_main.send(Err(error));
        }
    })?;
    drop(load_tx);
    wait_receiver(&load_rx, clock, cancellation, "load")
}

fn start_load_on_main(
    mtm: MainThreadMarker,
    job_id: &str,
    sender: Sender<Result<(), RenderError>>,
) -> Result<(), RenderError> {
    let _ = mtm;
    let Some((webview, delegate)) = SESSIONS.with(|sessions| {
        sessions
            .borrow()
            .get(job_id)
            .map(|session| (session.webview.clone(), session.delegate.clone()))
    }) else {
        return Err(missing_session(job_id));
    };
    delegate.begin_load(sender);
    let Some(url) = NSURL::URLWithString(&NSString::from_str(&format!(
        "{RENDER_SCHEME}://{job_id}/{RENDER_DOCUMENT_PATH}"
    ))) else {
        delegate.fail_pending("render URL could not be created");
        return Ok(());
    };
    let request = NSURLRequest::requestWithURL_cachePolicy_timeoutInterval(
        &url,
        NSURLRequestCachePolicy::ReloadIgnoringLocalCacheData,
        15.0,
    );
    if unsafe { webview.loadRequest(&request) }.is_none() {
        delegate.fail_pending("WKWebView.loadRequest returned nil");
    }
    Ok(())
}

fn async_main<T, F>(
    app: &AppHandle,
    clock: Clock,
    cancellation: &CancellationToken,
    phase: &'static str,
    setup: F,
) -> Result<T, RenderError>
where
    T: Send + 'static,
    F: FnOnce(MainThreadMarker, Sender<Result<T, RenderError>>) -> Result<(), RenderError>
        + Send
        + 'static,
{
    let (tx, rx) = mpsc::channel();
    let tx_for_main = tx.clone();
    dispatch(app, clock, phase, move |mtm| {
        let fallback = tx_for_main.clone();
        if let Err(error) = setup(mtm, tx_for_main) {
            let _ = fallback.send(Err(error));
        }
    })?;
    drop(tx);
    wait_receiver(&rx, clock, cancellation, phase)
}

fn dispatch<F>(app: &AppHandle, clock: Clock, phase: &'static str, f: F) -> Result<(), RenderError>
where
    F: FnOnce(MainThreadMarker) + Send + 'static,
{
    let (ack_tx, ack_rx) = mpsc::channel();
    app.run_on_main_thread(move || {
        let Some(mtm) = MainThreadMarker::new() else {
            let _ = ack_tx.send(Err(RenderError::Native {
                phase: phase.to_owned(),
                detail: "main-thread dispatch did not run on the AppKit main thread".to_owned(),
            }));
            return;
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| f(mtm)));
        let result = match outcome {
            Ok(()) => Ok(()),
            Err(_) => Err(RenderError::Native {
                phase: phase.to_owned(),
                detail: "main-thread callback panicked".to_owned(),
            }),
        };
        let _ = ack_tx.send(result);
    })
    .map_err(|error| RenderError::Native {
        phase: phase.to_owned(),
        detail: format!("run_on_main_thread failed: {error}"),
    })?;
    let bound = clock
        .remaining()
        .min(Duration::from_secs(10))
        .max(Duration::from_millis(50));
    match ack_rx.recv_timeout(bound) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(clock.timeout(phase)),
        Err(RecvTimeoutError::Disconnected) => Err(RenderError::Native {
            phase: phase.to_owned(),
            detail: "main-thread dispatch ended without a result".to_owned(),
        }),
    }
}

fn wait_receiver<T>(
    receiver: &Receiver<Result<T, RenderError>>,
    clock: Clock,
    cancellation: &CancellationToken,
    phase: &str,
) -> Result<T, RenderError> {
    loop {
        check_cancel(cancellation)?;
        let now = Instant::now();
        if now >= clock.deadline {
            return Err(clock.timeout(phase));
        }
        let slice = clock
            .deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(25));
        match receiver.recv_timeout(slice) {
            Ok(result) => return result,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                return Err(RenderError::Native {
                    phase: phase.to_owned(),
                    detail: "native callback ended without a result".to_owned(),
                });
            }
        }
    }
}

fn start_evaluate_on_main(
    mtm: MainThreadMarker,
    job_id: &str,
    script: &'static str,
    async_probe: bool,
    sender: Sender<Result<String, RenderError>>,
) -> Result<(), RenderError> {
    let session = SESSIONS
        .with(|sessions| {
            sessions
                .borrow()
                .get(job_id)
                .map(|session| session.webview.clone())
        })
        .ok_or_else(|| missing_session(job_id))?;
    let world = if async_probe {
        unsafe { WKContentWorld::pageWorld(mtm) }
    } else {
        unsafe { WKContentWorld::worldWithName(&NSString::from_str("h3-render-evidence"), mtm) }
    };
    let block = RcBlock::new(move |value: *mut AnyObject, error: *mut NSError| {
        let result = if !error.is_null() {
            Err(RenderError::Native {
                phase: "javascript".to_owned(),
                detail: unsafe { (&*error).localizedDescription().to_string() },
            })
        } else if value.is_null() {
            Err(RenderError::Native {
                phase: "javascript".to_owned(),
                detail: "evaluateJavaScript returned nil".to_owned(),
            })
        } else {
            let value = unsafe { &*value };
            value
                .downcast_ref::<NSString>()
                .map(|text| text.to_string())
                .ok_or_else(|| RenderError::Native {
                    phase: "javascript".to_owned(),
                    detail: "evaluateJavaScript returned a non-string result".to_owned(),
                })
        };
        let _ = sender.send(result);
    });
    if async_probe {
        let job = NSString::from_str(job_id);
        let other = NSString::from_str(&other_job_id(job_id));
        let arguments: Retained<NSDictionary<NSString, AnyObject>> = NSDictionary::from_slices(
            &[
                &*NSString::from_str("job"),
                &*NSString::from_str("otherJob"),
            ],
            &[as_any(&job), as_any(&other)],
        );
        unsafe {
            session.callAsyncJavaScript_arguments_inFrame_inContentWorld_completionHandler(
                &NSString::from_str(script),
                Some(&arguments),
                None,
                &world,
                Some(&block),
            );
        }
    } else {
        unsafe {
            session.evaluateJavaScript_inFrame_inContentWorld_completionHandler(
                &NSString::from_str(script),
                None,
                &world,
                Some(&block),
            );
        }
    }
    Ok(())
}

fn other_job_id(job_id: &str) -> String {
    if job_id == "0".repeat(32) {
        "f".repeat(32)
    } else {
        "0".repeat(32)
    }
}

fn as_any(object: &NSString) -> &AnyObject {
    unsafe { &*(object as *const NSString).cast::<AnyObject>() }
}

fn start_snapshot_on_main(
    mtm: MainThreadMarker,
    job_id: &str,
    sender: Sender<Result<(Vec<u8>, u32, u32), RenderError>>,
) -> Result<(), RenderError> {
    let session = SESSIONS
        .with(|sessions| {
            sessions
                .borrow()
                .get(job_id)
                .map(|session| session.webview.clone())
        })
        .ok_or_else(|| missing_session(job_id))?;
    let configuration = unsafe { WKSnapshotConfiguration::new(mtm) };
    unsafe { configuration.setAfterScreenUpdates(true) };
    let block = RcBlock::new(move |image: *mut NSImage, error: *mut NSError| {
        let result = if !error.is_null() {
            Err(RenderError::Native {
                phase: "snapshot".to_owned(),
                detail: unsafe { (&*error).localizedDescription().to_string() },
            })
        } else if image.is_null() {
            Err(RenderError::IncompleteCapture {
                detail: "takeSnapshot returned nil".to_owned(),
            })
        } else {
            let image = unsafe { &*image };
            image_to_png(image).ok_or_else(|| RenderError::IncompleteCapture {
                detail: "snapshot could not be encoded as PNG".to_owned(),
            })
        };
        let _ = sender.send(result);
    });
    unsafe {
        session.takeSnapshotWithConfiguration_completionHandler(Some(&configuration), &block);
    }
    Ok(())
}

fn image_to_png(image: &NSImage) -> Option<(Vec<u8>, u32, u32)> {
    let tiff = image.TIFFRepresentation()?;
    let representation = NSBitmapImageRep::initWithData(NSBitmapImageRep::alloc(), &tiff)?;
    let properties: Retained<NSDictionary<NSString, AnyObject>> =
        NSDictionary::from_slices::<NSString>(&[], &[]);
    let png = unsafe {
        representation.representationUsingType_properties(NSBitmapImageFileType::PNG, &properties)
    }?;
    let width = representation.pixelsWide();
    let height = representation.pixelsHigh();
    if width <= 0 || height <= 0 {
        return None;
    }
    Some((png.to_vec(), width as u32, height as u32))
}

fn settle(clock: Clock, cancellation: &CancellationToken) -> Result<(), RenderError> {
    let deadline = Instant::now() + SETTLE;
    loop {
        check_cancel(cancellation)?;
        clock.check("settle")?;
        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(25)));
    }
}

fn parse_json(value: &str, label: &str) -> Result<Value, RenderError> {
    serde_json::from_str(value).map_err(|error| RenderError::IncompleteCapture {
        detail: format!("{label} was not valid JSON: {error}"),
    })
}

fn css_viewport(dom: &Value) -> Result<CssViewport, RenderError> {
    let viewport = dom
        .get("viewport")
        .ok_or_else(|| RenderError::IncompleteCapture {
            detail: "dom metrics has no viewport".to_owned(),
        })?;
    Ok(CssViewport {
        inner_width: u32_field(viewport, "innerWidth")?,
        inner_height: u32_field(viewport, "innerHeight")?,
        device_pixel_ratio: f64_field(viewport, "devicePixelRatio")?,
        scroll_width: u32_field(viewport, "scrollWidth")?,
        scroll_height: u32_field(viewport, "scrollHeight")?,
    })
}

fn browser_evidence(dom: &Value) -> Result<BrowserEvidence, RenderError> {
    let navigator = dom
        .get("navigator")
        .ok_or_else(|| RenderError::IncompleteCapture {
            detail: "dom metrics has no navigator".to_owned(),
        })?;
    let user_agent = string_field(navigator, "userAgent")?;
    let rules: Vec<Value> = serde_json::from_str(CONTENT_RULES_JSON).unwrap_or_default();
    Ok(BrowserEvidence {
        webkit_version: webkit_version(&user_agent),
        user_agent,
        app_version: string_field(navigator, "appVersion")?,
        platform: string_field(navigator, "platform")?,
        language: string_field(navigator, "language")?,
        device_pixel_ratio: dom
            .get("viewport")
            .map(|viewport| f64_field(viewport, "devicePixelRatio"))
            .transpose()?
            .unwrap_or(0.0),
        java_script_enabled: true,
        java_script_can_open_windows: false,
        content_rule_list_identifier: CONTENT_RULE_LIST_IDENTIFIER.to_owned(),
        content_rule_list_compiled: true,
        content_rule_list_rule_count: rules.len() as u32,
        content_rule_list: rules,
        injected_user_script_count: 0,
        tauri_ipc_injected: false,
    })
}

fn webkit_version(user_agent: &str) -> Option<String> {
    let marker = "AppleWebKit/";
    let start = user_agent.find(marker)? + marker.len();
    let rest = &user_agent[start..];
    let end = rest
        .find(|character: char| character.is_whitespace() || character == ')')
        .unwrap_or(rest.len());
    let version = &rest[..end];
    (!version.is_empty()).then(|| version.to_owned())
}

fn verify_ipc(probe: &str) -> Result<(), RenderError> {
    let value = parse_json(probe, "protocol probe")?;
    let ipc = value
        .get("ipc")
        .ok_or_else(|| RenderError::IncompleteCapture {
            detail: "protocol probe has no ipc object".to_owned(),
        })?;
    for field in [
        "tauriInternals",
        "tauriGlobal",
        "ipcGlobal",
        "isTauri",
        "invoke",
    ] {
        let observed = ipc.get(field).and_then(Value::as_str);
        if observed != Some("undefined") {
            return Err(RenderError::IncompleteCapture {
                detail: format!("render webview exposes `{field}` ({observed:?})"),
            });
        }
    }
    Ok(())
}

fn verify_protocol(probe: &str, _payload: &RenderPayload) -> Result<(), RenderError> {
    let value = parse_json(probe, "protocol probe")?;
    let protocol = value
        .get("protocol")
        .and_then(Value::as_array)
        .ok_or_else(|| RenderError::IncompleteCapture {
            detail: "protocol probe has no requests".to_owned(),
        })?;
    let status = |suffix: &str| -> Option<u64> {
        protocol.iter().find_map(|entry| {
            let url = entry.get("url").and_then(Value::as_str)?;
            if url.ends_with(suffix) {
                entry.get("status").and_then(Value::as_u64)
            } else {
                None
            }
        })
    };
    // A real semantic-v1 candidate must carry a restrictive CSP
    // (`default-src 'none'`), so its page-world fetch of the custom scheme may
    // be refused before the router answers. In that case the probe records no
    // status. The authoritative rejection proof is the native router self-probe
    // (`missing_resource_status == 404`), checked by
    // `verify_protocol_evidence`; a status that *was* observed must still be 404.
    let missing = status("/missing.png");
    if missing.is_some_and(|status| status != 404) {
        return Err(RenderError::IncompleteCapture {
            detail: format!("missing resource probe returned {missing:?}, expected 404"),
        });
    }
    // The unknown-job rejection is proved by the native handler log; a
    // cross-origin probe may not expose the status code to page JavaScript.

    Ok(())
}

fn verify_protocol_evidence(evidence: &ProtocolEvidence) -> Result<(), RenderError> {
    let probe = &evidence.router_self_probe;
    if probe.unknown_job_status != 403
        || probe.path_escape_status != 400
        || probe.missing_resource_status != 404
        || probe.non_candidate_status != 404
    {
        return Err(RenderError::IncompleteCapture {
            detail: format!("router self-probe failed: {probe:?}"),
        });
    }
    // A restrictive candidate CSP can stop the page-world fetch before it
    // reaches the router. The native in-memory router self-probe above is the
    // authoritative rejection evidence; page-level records are an additional
    // proof when the candidate CSP allows them to arrive.
    if !evidence.unknown_job_rejected && probe.unknown_job_status != 403 {
        return Err(RenderError::IncompleteCapture {
            detail: "the unknown-job rejection was not observed".to_owned(),
        });
    }
    if !evidence.missing_resource_rejected && probe.missing_resource_status != 404 {
        return Err(RenderError::IncompleteCapture {
            detail: "the missing-resource rejection was not observed".to_owned(),
        });
    }
    if !evidence.non_candidate_rejected && probe.non_candidate_status != 404 {
        return Err(RenderError::IncompleteCapture {
            detail: "the non-candidate rejection was not observed".to_owned(),
        });
    }
    Ok(())
}

fn string_field(value: &Value, field: &str) -> Result<String, RenderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| RenderError::IncompleteCapture {
            detail: format!("evidence field `{field}` is missing"),
        })
}

fn f64_field(value: &Value, field: &str) -> Result<f64, RenderError> {
    value
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| RenderError::IncompleteCapture {
            detail: format!("evidence field `{field}` is missing"),
        })
}

fn u32_field(value: &Value, field: &str) -> Result<u32, RenderError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .ok_or_else(|| RenderError::IncompleteCapture {
            detail: format!("evidence field `{field}` is missing"),
        })
}

#[derive(Debug, Clone, Copy, Default)]
struct BlockCounts {
    new_windows: u32,
    downloads: u32,
    navigations: u32,
    responses: u32,
}

impl BlockCounts {
    fn delta(self, previous: Self) -> Self {
        Self {
            new_windows: self.new_windows.saturating_sub(previous.new_windows),
            downloads: self.downloads.saturating_sub(previous.downloads),
            navigations: self.navigations.saturating_sub(previous.navigations),
            responses: self.responses.saturating_sub(previous.responses),
        }
    }
}

fn block_counts(
    app: &AppHandle,
    job_id: &str,
    clock: Clock,
    cancellation: &CancellationToken,
) -> Result<BlockCounts, RenderError> {
    let job_id = job_id.to_owned();
    async_main(
        app,
        clock,
        cancellation,
        "delegate_counts",
        move |_mtm, sender| {
            let counts = SESSIONS.with(|sessions| {
                sessions.borrow().get(&job_id).map(|session| BlockCounts {
                    new_windows: session.log.new_windows.load(Ordering::SeqCst) as u32,
                    downloads: session.log.downloads.load(Ordering::SeqCst) as u32,
                    navigations: session
                        .log
                        .blocked_navigations
                        .lock()
                        .map(|entries| entries.len() as u32)
                        .unwrap_or(0),
                    responses: session
                        .log
                        .blocked_responses
                        .lock()
                        .map(|entries| entries.len() as u32)
                        .unwrap_or(0),
                })
            });
            let _ = sender.send(counts.ok_or_else(|| missing_session(&job_id)));
            Ok(())
        },
    )
}

fn teardown(app: &AppHandle, job_id: &str) -> Result<(), RenderError> {
    let job_id = job_id.to_owned();
    let (tx, rx) = mpsc::channel();
    app.run_on_main_thread(move || {
        teardown_on_main(&job_id);
        let _ = tx.send(());
    })
    .map_err(|error| RenderError::Native {
        phase: "teardown".to_owned(),
        detail: format!("run_on_main_thread failed: {error}"),
    })?;
    rx.recv_timeout(Duration::from_secs(2))
        .map_err(|_| RenderError::Native {
            phase: "teardown".to_owned(),
            detail: "teardown did not complete on the main thread".to_owned(),
        })
}

fn teardown_on_main(job_id: &str) {
    let session = SESSIONS.with(|sessions| sessions.borrow_mut().remove(job_id));
    if let Some(session) = session {
        unsafe {
            session.webview.stopLoading();
            session.webview.setNavigationDelegate(None);
            session.webview.setUIDelegate(None);
        }
        session.delegate.fail_pending("render view closed");
        session.webview.removeFromSuperview();
        session.window.setContentView(None);
        session.window.orderOut(None);
    }
    isolation::close_aux_on_main();
}

mod isolation {
    use super::*;

    pub(super) fn run(
        app: &AppHandle,
        job_id: &str,
        clock: Clock,
        cancellation: &CancellationToken,
    ) -> Result<IsolationEvidence, RenderError> {
        let job_id = job_id.to_owned();
        async_main(app, clock, cancellation, "isolation_prepare", {
            let job_id = job_id.clone();
            move |mtm, sender| {
                let result = prepare_aux_on_main(mtm, &job_id);
                let _ = sender.send(result);
                Ok(())
            }
        })?;

        load_aux(
            app,
            AuxKind::Control,
            CONTROL_SEED_HTML,
            clock,
            cancellation,
        )?;
        load_aux(app, AuxKind::Render, RENDER_SEED_HTML, clock, cancellation)?;

        let render_read = evaluate_aux(
            app,
            AuxKind::Render,
            RENDER_READ_SCRIPT,
            clock,
            cancellation,
        )?;
        let control_read = evaluate_aux(
            app,
            AuxKind::Control,
            CONTROL_READ_SCRIPT,
            clock,
            cancellation,
        )?;
        let (render_main, render_self) = read_storage_pair(&render_read, "render")?;
        let (control_main, control_render) = read_storage_pair(&control_read, "control")?;

        set_cookie_on_main(
            app,
            AuxKind::Control,
            MAIN_COOKIE,
            "main-value",
            clock,
            cancellation,
        )?;
        let render_cookies = get_cookies_on_main(app, AuxKind::Render, clock, cancellation)?;
        set_cookie_on_main(
            app,
            AuxKind::Render,
            RENDER_COOKIE,
            "render-value",
            clock,
            cancellation,
        )?;
        let main_cookies = get_cookies_on_main(app, AuxKind::Control, clock, cancellation)?;
        let render_cookies_after = get_cookies_on_main(app, AuxKind::Render, clock, cancellation)?;

        let mut notes = Vec::new();
        if let Err(error) =
            delete_cookie_on_main(app, AuxKind::Control, MAIN_COOKIE, clock, cancellation)
        {
            notes.push(format!(
                "could not remove the control-store probe cookie: {error}"
            ));
        }
        if let Err(error) =
            delete_cookie_on_main(app, AuxKind::Render, RENDER_COOKIE, clock, cancellation)
        {
            notes.push(format!(
                "could not remove the render-store probe cookie: {error}"
            ));
        }
        if let Err(error) = cleanup_local_storage(app, AuxKind::Control, clock, cancellation) {
            notes.push(format!(
                "could not remove control-store local storage: {error}"
            ));
        }

        let (render_store_persistent, control_store_persistent, render_store_is_default_store) =
            aux_store_facts(app, clock, cancellation)?;
        close_aux(app, clock, cancellation)?;

        let main_store_sees_its_cookie = main_cookies.iter().any(|(name, _)| name == MAIN_COOKIE);
        let render_store_sees_its_cookie = render_cookies_after
            .iter()
            .any(|(name, _)| name == RENDER_COOKIE);
        let main_cookie_visible_in_render =
            render_cookies.iter().any(|(name, _)| name == MAIN_COOKIE);
        let render_cookie_visible_in_main =
            main_cookies.iter().any(|(name, _)| name == RENDER_COOKIE);
        let main_store_sees_its_local_storage = control_main.as_deref() == Some("main-store");
        let render_store_sees_its_local_storage = render_self.as_deref() == Some("render-store");
        let main_local_storage_visible_in_render = render_main.is_some();
        let render_local_storage_visible_in_main = control_render.is_some();

        notes.push(format!(
            "control cookies observed={}, render cookies before its write={}, after its write={}",
            main_cookies.len(),
            render_cookies.len(),
            render_cookies_after.len()
        ));

        Ok(IsolationEvidence {
            render_store_persistent,
            render_store_is_default_store,
            control_store_persistent,
            main_store_sees_its_cookie,
            render_store_sees_its_cookie,
            main_store_sees_its_local_storage,
            render_store_sees_its_local_storage,
            main_cookie_visible_in_render,
            render_cookie_visible_in_main,
            main_local_storage_visible_in_render,
            render_local_storage_visible_in_main,
            main_local_storage_value_observed_by_render: render_main,
            render_local_storage_value_observed_by_control: control_render,
            notes,
        })
    }

    fn prepare_aux_on_main(mtm: MainThreadMarker, job_id: &str) -> Result<(), RenderError> {
        let render_store = SESSIONS
            .with(|sessions| {
                sessions
                    .borrow()
                    .get(job_id)
                    .map(|session| session.store.clone())
            })
            .ok_or_else(|| missing_session(job_id))?;
        let default_store = unsafe { WKWebsiteDataStore::defaultDataStore(mtm) };

        let control = create_aux(mtm, default_store, AUX_CONTROL_Y)?;
        let render = create_aux(mtm, render_store, AUX_RENDER_Y)?;
        AUX_SESSIONS.with(|sessions| {
            let mut sessions = sessions.borrow_mut();
            sessions.insert(AuxKind::Control, control);
            sessions.insert(AuxKind::Render, render);
        });
        Ok(())
    }

    fn create_aux(
        mtm: MainThreadMarker,
        store: Retained<WKWebsiteDataStore>,
        y: f64,
    ) -> Result<AuxSession, RenderError> {
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                mtm.alloc::<NSWindow>(),
                objc2_foundation::NSRect::new(
                    objc2_foundation::NSPoint::new(WINDOW_X, y),
                    objc2_foundation::NSSize::new(AUX_WIDTH, AUX_HEIGHT),
                ),
                NSWindowStyleMask::Borderless,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        unsafe { window.setReleasedWhenClosed(false) };
        window.setOpaque(true);
        window.setIgnoresMouseEvents(true);
        window.setCanHide(false);
        window.setHidesOnDeactivate(false);

        let configuration = unsafe { WKWebViewConfiguration::new(mtm) };
        unsafe {
            let preferences: Retained<WKWebpagePreferences> =
                configuration.defaultWebpagePreferences();
            preferences.setAllowsContentJavaScript(true);
            configuration.setWebsiteDataStore(&store);
        }
        let frame = objc2_foundation::NSRect::new(
            objc2_foundation::NSPoint::new(0.0, 0.0),
            objc2_foundation::NSSize::new(AUX_WIDTH, AUX_HEIGHT),
        );
        let webview = unsafe {
            WKWebView::initWithFrame_configuration(mtm.alloc::<WKWebView>(), frame, &configuration)
        };
        let delegate = AuxDelegate::new(mtm, Arc::new(DelegateLog::default()));
        unsafe {
            webview.setNavigationDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        }
        window.setContentView(Some(webview.as_super()));
        window.orderFrontRegardless();
        Ok(AuxSession {
            window,
            webview,
            delegate,
            store,
        })
    }

    fn load_aux(
        app: &AppHandle,
        kind: AuxKind,
        html: &'static str,
        clock: Clock,
        cancellation: &CancellationToken,
    ) -> Result<(), RenderError> {
        let (load_tx, load_rx) = mpsc::channel();
        let load_tx_for_main = load_tx.clone();
        dispatch(app, clock, "isolation_load", move |mtm| {
            let Some(session) = AUX_SESSIONS.with(|sessions| {
                sessions
                    .borrow()
                    .get(&kind)
                    .map(|session| (session.webview.clone(), session.delegate.clone()))
            }) else {
                let _ = load_tx_for_main.send(Err(RenderError::Native {
                    phase: "isolation_load".to_owned(),
                    detail: "isolation view is missing".to_owned(),
                }));
                return;
            };
            let _ = mtm;
            session.1.begin_load(load_tx_for_main.clone());
            let Some(base) = NSURL::URLWithString(&NSString::from_str(ISOLATION_ORIGIN)) else {
                let error = unsafe {
                    NSError::errorWithDomain_code_userInfo(
                        &NSString::from_str("dev.herness.h3render"),
                        -2,
                        None,
                    )
                };
                session.1.fail(&error);
                return;
            };
            if unsafe {
                session
                    .0
                    .loadHTMLString_baseURL(&NSString::from_str(html), Some(&base))
            }
            .is_none()
            {
                let error = unsafe {
                    NSError::errorWithDomain_code_userInfo(
                        &NSString::from_str("dev.herness.h3render"),
                        -3,
                        None,
                    )
                };
                session.1.fail(&error);
            }
        })?;
        drop(load_tx);
        wait_receiver(&load_rx, clock, cancellation, "isolation_load")
    }

    fn evaluate_aux(
        app: &AppHandle,
        kind: AuxKind,
        script: &'static str,
        clock: Clock,
        cancellation: &CancellationToken,
    ) -> Result<String, RenderError> {
        async_main(
            app,
            clock,
            cancellation,
            "isolation_evaluate",
            move |_mtm, sender| {
                let Some(webview) = AUX_SESSIONS.with(|sessions| {
                    sessions
                        .borrow()
                        .get(&kind)
                        .map(|session| session.webview.clone())
                }) else {
                    let _ = sender.send(Err(RenderError::Native {
                        phase: "isolation_evaluate".to_owned(),
                        detail: "isolation view is missing".to_owned(),
                    }));
                    return Ok(());
                };
                let block = RcBlock::new(move |value: *mut AnyObject, error: *mut NSError| {
                    let result = if !error.is_null() {
                        Err(RenderError::Native {
                            phase: "isolation_evaluate".to_owned(),
                            detail: unsafe { (&*error).localizedDescription().to_string() },
                        })
                    } else if value.is_null() {
                        Err(RenderError::Native {
                            phase: "isolation_evaluate".to_owned(),
                            detail: "isolation JavaScript returned nil".to_owned(),
                        })
                    } else {
                        let value = unsafe { &*value };
                        value
                            .downcast_ref::<NSString>()
                            .map(|text| text.to_string())
                            .ok_or_else(|| RenderError::Native {
                                phase: "isolation_evaluate".to_owned(),
                                detail: "isolation JavaScript returned a non-string result"
                                    .to_owned(),
                            })
                    };
                    let _ = sender.send(result);
                });
                unsafe {
                    webview.evaluateJavaScript_completionHandler(
                        &NSString::from_str(script),
                        Some(&block),
                    );
                }
                Ok(())
            },
        )
    }

    fn read_storage_pair(
        raw: &str,
        label: &str,
    ) -> Result<(Option<String>, Option<String>), RenderError> {
        let value: Value =
            serde_json::from_str(raw).map_err(|error| RenderError::IncompleteCapture {
                detail: format!("{label} storage probe was not valid JSON: {error}"),
            })?;
        let read = |field: &str| {
            value
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .filter(|value| !value.is_empty() && !value.starts_with("error:"))
        };
        Ok((read("main"), read("render")))
    }

    fn set_cookie_on_main(
        app: &AppHandle,
        kind: AuxKind,
        name: &'static str,
        value: &'static str,
        clock: Clock,
        cancellation: &CancellationToken,
    ) -> Result<(), RenderError> {
        async_main(
            app,
            clock,
            cancellation,
            "isolation_cookie",
            move |_mtm, sender| {
                let Some(store) = aux_store(kind) else {
                    let _ = sender.send(Err(RenderError::Native {
                        phase: "isolation_cookie".to_owned(),
                        detail: "isolation store is missing".to_owned(),
                    }));
                    return Ok(());
                };
                let cookie = match make_cookie(name, value) {
                    Ok(cookie) => cookie,
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        return Ok(());
                    }
                };
                let block = RcBlock::new(move || {
                    let _ = sender.send(Ok(()));
                });
                unsafe {
                    store
                        .httpCookieStore()
                        .setCookie_completionHandler(&cookie, Some(&block));
                }
                Ok(())
            },
        )
    }

    fn get_cookies_on_main(
        app: &AppHandle,
        kind: AuxKind,
        clock: Clock,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(String, String)>, RenderError> {
        async_main(
            app,
            clock,
            cancellation,
            "isolation_cookie",
            move |_mtm, sender| {
                let Some(store) = aux_store(kind) else {
                    let _ = sender.send(Err(RenderError::Native {
                        phase: "isolation_cookie".to_owned(),
                        detail: "isolation store is missing".to_owned(),
                    }));
                    return Ok(());
                };
                let block = RcBlock::new(move |cookies: NonNull<NSArray<NSHTTPCookie>>| {
                    let cookies = unsafe { cookies.as_ref() };
                    let values = cookies
                        .iter()
                        .map(|cookie| (cookie.name().to_string(), cookie.value().to_string()))
                        .collect();
                    let _ = sender.send(Ok(values));
                });
                unsafe {
                    store.httpCookieStore().getAllCookies(&block);
                }
                Ok(())
            },
        )
    }

    fn delete_cookie_on_main(
        app: &AppHandle,
        kind: AuxKind,
        name: &'static str,
        clock: Clock,
        cancellation: &CancellationToken,
    ) -> Result<(), RenderError> {
        let cookies = get_cookies_on_main(app, kind, clock, cancellation)?;
        if !cookies.iter().any(|(cookie_name, _)| cookie_name == name) {
            return Ok(());
        }
        async_main(
            app,
            clock,
            cancellation,
            "isolation_cookie",
            move |_mtm, sender| {
                let Some(store) = aux_store(kind) else {
                    let _ = sender.send(Err(RenderError::Native {
                        phase: "isolation_cookie".to_owned(),
                        detail: "isolation store is missing".to_owned(),
                    }));
                    return Ok(());
                };
                let store_for_block = store.clone();
                let block = RcBlock::new(move |cookies: NonNull<NSArray<NSHTTPCookie>>| {
                    let cookies = unsafe { cookies.as_ref() };
                    let Some(cookie) = cookies
                        .iter()
                        .find(|cookie| cookie.name().to_string() == name)
                    else {
                        let _ = sender.send(Ok(()));
                        return;
                    };
                    let cookie = cookie.retain();
                    let nested_sender = sender.clone();
                    let done = RcBlock::new(move || {
                        let _ = nested_sender.send(Ok(()));
                    });
                    unsafe {
                        store_for_block
                            .httpCookieStore()
                            .deleteCookie_completionHandler(&cookie, Some(&done));
                    }
                });
                unsafe {
                    store.httpCookieStore().getAllCookies(&block);
                }
                Ok(())
            },
        )
    }

    fn cleanup_local_storage(
        app: &AppHandle,
        kind: AuxKind,
        clock: Clock,
        cancellation: &CancellationToken,
    ) -> Result<(), RenderError> {
        async_main(
            app,
            clock,
            cancellation,
            "isolation_cleanup",
            move |_mtm, sender| {
                let Some(store) = aux_store(kind) else {
                    let _ = sender.send(Ok(()));
                    return Ok(());
                };
                let types =
                    NSSet::from_slice(&[&*NSString::from_str("WKWebsiteDataTypeLocalStorage")]);
                let types_for_block = types.clone();
                let store_for_block = store.clone();
                let block = RcBlock::new(move |records: NonNull<NSArray<WKWebsiteDataRecord>>| {
                    let records = unsafe { records.as_ref() };
                    let matching: Vec<Retained<WKWebsiteDataRecord>> = records
                        .iter()
                        .filter(|record| unsafe {
                            record.displayName().to_string() == "h3-isolation.test"
                        })
                        .map(|record| record.retain())
                        .collect();
                    if matching.is_empty() {
                        let _ = sender.send(Ok(()));
                        return;
                    }
                    let array = NSMutableArray::from_retained_slice(&matching);
                    let nested_sender = sender.clone();
                    let done = RcBlock::new(move || {
                        let _ = nested_sender.send(Ok(()));
                    });
                    unsafe {
                        store_for_block.removeDataOfTypes_forDataRecords_completionHandler(
                            &types_for_block,
                            &array,
                            &done,
                        );
                    }
                });
                unsafe {
                    store.fetchDataRecordsOfTypes_completionHandler(&types, &block);
                }
                Ok(())
            },
        )
    }

    fn aux_store_facts(
        app: &AppHandle,
        clock: Clock,
        cancellation: &CancellationToken,
    ) -> Result<(bool, bool, bool), RenderError> {
        async_main(
            app,
            clock,
            cancellation,
            "isolation_store",
            move |mtm, sender| {
                let result = (|| -> Result<(bool, bool, bool), RenderError> {
                    let render = aux_store(AuxKind::Render).ok_or_else(|| RenderError::Native {
                        phase: "isolation_store".to_owned(),
                        detail: "render isolation store is missing".to_owned(),
                    })?;
                    let control =
                        aux_store(AuxKind::Control).ok_or_else(|| RenderError::Native {
                            phase: "isolation_store".to_owned(),
                            detail: "control isolation store is missing".to_owned(),
                        })?;
                    let default = unsafe { WKWebsiteDataStore::defaultDataStore(mtm) };
                    Ok((
                        unsafe { render.isPersistent() },
                        unsafe { control.isPersistent() },
                        Retained::as_ptr(&render) == Retained::as_ptr(&default),
                    ))
                })();
                let _ = sender.send(result);
                Ok(())
            },
        )
    }

    fn close_aux(
        app: &AppHandle,
        clock: Clock,
        cancellation: &CancellationToken,
    ) -> Result<(), RenderError> {
        let _ = clock;
        let _ = cancellation;
        let (tx, rx) = mpsc::channel();
        app.run_on_main_thread(move || {
            close_aux_on_main();
            let _ = tx.send(());
        })
        .map_err(|error| RenderError::Native {
            phase: "isolation_close".to_owned(),
            detail: format!("run_on_main_thread failed: {error}"),
        })?;
        rx.recv_timeout(Duration::from_secs(2))
            .map_err(|_| RenderError::Native {
                phase: "isolation_close".to_owned(),
                detail: "auxiliary view cleanup did not complete".to_owned(),
            })
    }

    pub(super) fn close_aux_on_main() {
        let sessions = AUX_SESSIONS.with(|sessions| std::mem::take(&mut *sessions.borrow_mut()));
        for (_, session) in sessions {
            unsafe {
                session.webview.stopLoading();
                session.webview.setNavigationDelegate(None);
            }
            session.delegate.fail_pending("isolation view closed");
            session.webview.removeFromSuperview();
            session.window.setContentView(None);
            session.window.orderOut(None);
        }
    }

    fn aux_store(kind: AuxKind) -> Option<Retained<WKWebsiteDataStore>> {
        AUX_SESSIONS.with(|sessions| {
            sessions
                .borrow()
                .get(&kind)
                .map(|session| session.store.clone())
        })
    }

    fn make_cookie(name: &str, value: &str) -> Result<Retained<NSHTTPCookie>, RenderError> {
        let name = NSString::from_str(name);
        let value = NSString::from_str(value);
        let domain = NSString::from_str(COOKIE_DOMAIN);
        let path = NSString::from_str("/");
        let properties: Retained<NSMutableDictionary<NSHTTPCookiePropertyKey, AnyObject>> =
            NSMutableDictionary::new();
        unsafe {
            properties.insert(NSHTTPCookieName, as_any(&name));
            properties.insert(NSHTTPCookieValue, as_any(&value));
            properties.insert(NSHTTPCookieDomain, as_any(&domain));
            properties.insert(NSHTTPCookiePath, as_any(&path));
        }
        unsafe { NSHTTPCookie::initWithProperties(NSHTTPCookie::alloc(), &properties) }.ok_or_else(
            || RenderError::Native {
                phase: "isolation_cookie".to_owned(),
                detail: "NSHTTPCookie.initWithProperties returned nil".to_owned(),
            },
        )
    }
}
