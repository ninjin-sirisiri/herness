// H3 page-world protocol and IPC probe.
//
// This body is evaluated with `callAsyncJavaScript` in the page content world
// after the candidate has loaded; `job` and `otherJob` arrive through the
// arguments dictionary. It proves what the candidate itself can observe: there
// is no Tauri IPC surface, the job protocol rejects other jobs, escapes, and
// undeclared paths, and the page's own external-load attempts are blocked. The
// authoritative loopback count is measured outside the process.
"use strict";

const base = `h3render://${job}`;
const other = `h3render://${otherJob}`;

async function probe(url) {
  try {
    const response = await fetch(url, { cache: "no-store", credentials: "omit" });
    let bodyLength = null;
    try {
      bodyLength = (await response.text()).length;
    } catch (_error) {
      bodyLength = null;
    }
    return { url, status: response.status, ok: response.ok, bodyLength };
  } catch (error) {
    return { url, error: String((error && error.name) || error) };
  }
}

const protocol = [];
protocol.push(await probe(`${base}/index.html`));
protocol.push(await probe(`${base}/candidate.css`));
protocol.push(await probe(`${base}/assets/diagram.svg`));
protocol.push(await probe(`${base}/missing.png`));
protocol.push(await probe(`${base}/secret.txt`));
protocol.push(await probe(`${base}/../secret.txt`));
protocol.push(await probe(`${base}/%2e%2e/secret.txt`));
protocol.push(await probe(`${other}/index.html`));

const ipc = {
  tauriInternals: typeof window.__TAURI_INTERNALS__,
  tauriGlobal: typeof window.__TAURI__,
  ipcGlobal: typeof window.ipc,
  isTauri: typeof window.isTauri,
  invoke: (() => {
    try {
      return typeof (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke);
    } catch (_error) {
      return "error";
    }
  })(),
};

let localStorageStatus = "unavailable";
try {
  localStorage.setItem("h3-render-probe", "probe");
  localStorageStatus = localStorage.getItem("h3-render-probe") === "probe" ? "writable" : "mismatch";
  localStorage.removeItem("h3-render-probe");
} catch (error) {
  localStorageStatus = `error:${(error && error.name) || "unknown"}`;
}

return JSON.stringify({
  scriptVersion: "h3-render-protocol-probe-v1",
  protocol,
  ipc,
  candidateProbe: window.__H3_CANDIDATE_PROBE__ || null,
  storage: {
    localStorageStatus,
    localStorageLength: (() => {
      try {
        return localStorage.length;
      } catch (_error) {
        return null;
      }
    })(),
    cookie: (() => {
      try {
        return document.cookie;
      } catch (_error) {
        return "";
      }
    })(),
  },
  openedWindows: typeof window.open === "function" ? "available" : "unavailable",
});
