//! Loopback callback listener for the ChatGPT authorization code.
//!
//! The listener binds only `127.0.0.1` and keeps the scheme, host, and path
//! fixed. Only the port may vary. It accepts exactly one valid callback, sends
//! a small local response, and closes. It never contacts an OpenAI host.

use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::error::{AuthError, CallbackViolation};
use super::pkce::constant_time_eq;
use super::types::CALLBACK_PATH;

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Parsed callback query.
#[derive(Clone)]
pub struct AuthorizationCallback {
    code: Option<String>,
    state: String,
    client_id: Option<String>,
    scope: Option<String>,
    error: Option<String>,
}

impl AuthorizationCallback {
    /// Authorization code. This is a secret and is deliberately only available
    /// to the flow implementation.
    pub(crate) fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// State returned by the authorization server.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Issued client ID returned by new registration, if present.
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// Granted scope value returned on the callback, if present.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// OAuth error code, if the authorization was not granted.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Whether the callback matches a state value without exposing either
    /// value to formatting.
    pub fn matches_state(&self, expected: &str) -> bool {
        constant_time_eq(self.state(), expected)
    }
}

impl fmt::Debug for AuthorizationCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationCallback")
            .field("code", &self.code.as_ref().map(|_| "[REDACTED]"))
            .field("state", &"[REDACTED]")
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("error", &self.error)
            .finish()
    }
}

#[derive(Debug, Default)]
struct ListenerState {
    listener: Option<TcpListener>,
    consumed: bool,
}

/// A bound loopback listener that is started before the browser is opened.
pub struct CallbackListener {
    state: Mutex<ListenerState>,
    port: u16,
    cancelled: Arc<AtomicBool>,
}

impl CallbackListener {
    /// Binds `127.0.0.1` on the preferred port, falling back to an
    /// operating-system-selected port when the preferred one is unavailable.
    ///
    /// The fallback never changes the scheme, host, or path.
    pub fn bind(preferred_port: Option<u16>) -> Result<Self, AuthError> {
        let listener = match preferred_port {
            Some(port) if port != 0 => match TcpListener::bind(("127.0.0.1", port)) {
                Ok(listener) => listener,
                Err(_) => TcpListener::bind(("127.0.0.1", 0))
                    .map_err(|_| AuthError::LoopbackBindFailed)?,
            },
            _ => TcpListener::bind(("127.0.0.1", 0)).map_err(|_| AuthError::LoopbackBindFailed)?,
        };
        listener
            .set_nonblocking(true)
            .map_err(|_| AuthError::LoopbackBindFailed)?;
        let port = listener
            .local_addr()
            .map_err(|_| AuthError::LoopbackBindFailed)?
            .port();
        Ok(Self {
            state: Mutex::new(ListenerState {
                listener: Some(listener),
                consumed: false,
            }),
            port,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Selected loopback port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Fixed callback URI for this attempt.
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{}", self.port, CALLBACK_PATH)
    }

    /// Whether the listener has been closed or consumed.
    pub fn is_closed(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.consumed || state.listener.is_none()
    }

    /// Waits for one valid callback request.
    pub fn wait(&self, timeout: Duration) -> Result<AuthorizationCallback, AuthError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(AuthError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(AuthError::CallbackTimeout);
            }
            let stream = {
                let state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if state.consumed {
                    return Err(AuthError::CallbackReplay);
                }
                let Some(listener) = state.listener.as_ref() else {
                    return Err(AuthError::Cancelled);
                };
                match listener.accept() {
                    Ok((stream, _)) => Some(stream),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
                    Err(_) => return Err(AuthError::CallbackTimeout),
                }
            };
            let Some(mut stream) = stream else {
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
                continue;
            };
            match read_callback_request(&mut stream) {
                Ok(Some(callback)) => {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if state.consumed {
                        let _ = write_response(&mut stream, 409, "already completed");
                        return Err(AuthError::CallbackReplay);
                    }
                    state.consumed = true;
                    state.listener = None;
                    let _ = write_response(&mut stream, 200, "You can return to herness.");
                    return Ok(callback);
                }
                Ok(None) => {
                    // Not the fixed callback path. Ignore it and keep waiting.
                    let _ = write_response(&mut stream, 404, "not found");
                }
                Err(error) => {
                    let _ = write_response(&mut stream, 400, "invalid callback");
                    return Err(error);
                }
            }
        }
    }

    /// Closes the listener and makes all later callbacks impossible.
    pub fn close(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.listener = None;
        state.consumed = true;
    }
}

fn read_callback_request(
    stream: &mut TcpStream,
) -> Result<Option<AuthorizationCallback>, AuthError> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > MAX_REQUEST_BYTES {
                    return Err(AuthError::InvalidCallback {
                        violation: CallbackViolation::WrongRequest,
                    });
                }
                if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                return Err(AuthError::InvalidCallback {
                    violation: CallbackViolation::WrongRequest,
                });
            }
        }
    }
    let request = String::from_utf8(buffer).map_err(|_| AuthError::InvalidCallback {
        violation: CallbackViolation::WrongRequest,
    })?;
    let request_line = request.lines().next().ok_or(AuthError::InvalidCallback {
        violation: CallbackViolation::WrongRequest,
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next();
    let target = parts.next();
    if method != Some("GET") {
        return Err(AuthError::InvalidCallback {
            violation: CallbackViolation::WrongRequest,
        });
    }
    let target = target.ok_or(AuthError::InvalidCallback {
        violation: CallbackViolation::WrongRequest,
    })?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != CALLBACK_PATH {
        return Ok(None);
    }
    parse_callback_query(query).map(Some)
}

fn parse_callback_query(query: &str) -> Result<AuthorizationCallback, AuthError> {
    let mut code = None;
    let mut state = None;
    let mut client_id = None;
    let mut scope = None;
    let mut error = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key).map_err(|_| AuthError::InvalidCallback {
            violation: CallbackViolation::MalformedQuery,
        })?;
        let value = percent_decode(value).map_err(|_| AuthError::InvalidCallback {
            violation: CallbackViolation::MalformedQuery,
        })?;
        let slot = match key.as_str() {
            "code" => &mut code,
            "state" => &mut state,
            "client_id" => &mut client_id,
            "scope" => &mut scope,
            "error" => &mut error,
            _ => continue,
        };
        if slot.is_some() {
            return Err(AuthError::InvalidCallback {
                violation: CallbackViolation::MalformedQuery,
            });
        }
        *slot = Some(value);
    }
    let state = state.ok_or(AuthError::InvalidCallback {
        violation: CallbackViolation::MalformedQuery,
    })?;
    if state.is_empty() {
        return Err(AuthError::InvalidCallback {
            violation: CallbackViolation::MalformedQuery,
        });
    }
    Ok(AuthorizationCallback {
        code,
        state,
        client_id,
        scope,
        error,
    })
}

fn percent_decode(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(());
                }
                let high = hex(bytes[index + 1])?;
                let low = hex(bytes[index + 2])?;
                output.push((high << 4) | low);
                index += 3;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output).map_err(|_| ())
}

fn hex(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

fn write_response(stream: &mut TcpStream, status: u16, message: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    let body = format!("<!doctype html><html><body><p>{message}</p></body></html>");
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}
