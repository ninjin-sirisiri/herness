// Minimal trusted main-window UI.
//
// All project, tool, and event text is rendered with textContent. Nothing is
// inserted as HTML, and no API key, token, or login URL is written to browser
// storage, cookies, or the DOM.

const invoke = window.__TAURI__ && window.__TAURI__.core
  ? window.__TAURI__.core.invoke
  : null;

const ui = {
  project: null,
  connection: null,
  connectionAuth: null,
  run: null,
};

function byId(id) {
  return document.getElementById(id);
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  if (className) {
    node.className = className;
  }
  return node;
}

function setText(id, text) {
  byId(id).textContent = text === undefined || text === null ? "" : String(text);
}

function clear(id) {
  byId(id).replaceChildren();
}

function showError(error) {
  setText("error-line", error === undefined || error === null ? "" : String(error));
}

function errorText(error) {
  return error && error.message ? error.message : String(error);
}

async function call(command, args) {
  if (!invoke) {
    throw new Error("Tauri IPC is unavailable in this document");
  }
  return invoke(command, args || {});
}

async function frontendState() {
  const state = await call("frontend_state");
  renderProjects(state.projects || []);
  renderConnections(state.connections || []);
  renderReconciliation(state.reconciliation);
  setText(
    "policy-line",
    `Permission mode: ${state.permissionMode} (policy ${state.policyVersion}) · ` +
      `Automatic decision: unavailable — ${state.automaticModeReason}`
  );
  if (state.selectedProject) {
    ui.project = state.selectedProject;
  }
  return state;
}

function renderReconciliation(report) {
  if (!report) {
    setText("reconciliation", "No restore report is available.");
    return;
  }
  const previous = report.previousShutdown;
  const lines = [];
  if (previous) {
    lines.push(
      `Previous shutdown: ${previous.outcome} · stopped runs: ${previous.stoppedRuns} · ` +
        `unconfirmed: ${(previous.unconfirmedRuns || []).length} · ` +
        `remaining: ${(previous.remainingRuns || []).length} · ` +
        `discarded host messages: ${previous.discardedDeferredMessages} · ` +
        `save failures: ${previous.saveFailures}`
    );
  } else {
    lines.push("Previous shutdown: none recorded.");
  }
  lines.push(`Discarded host-result messages: ${report.discardedDeferredMessages || 0}`);
  for (const project of report.projects || []) {
    lines.push(`Project ${project.path}`);
    for (const run of project.runs || []) {
      lines.push(
        `  run ${run.runId}: ${run.previousState} -> ${run.state}` +
          (run.awaitingApproval ? " (restored approval requires re-evaluation)" : "")
      );
    }
    for (const operation of project.operations || []) {
      lines.push(
        `  operation ${operation.operationId} (${operation.tool}): ` +
          `${operation.outcome} via ${operation.source}` +
          (operation.detail ? ` — ${operation.detail}` : "")
      );
    }
    for (const approval of project.pendingApprovals || []) {
      lines.push(
        `  pending approval ${approval.operation.operationId} (${approval.operation.tool}) · ` +
          `reusable: ${approval.reusable}`
      );
    }
  }
  setText("reconciliation", lines.join("\n"));
}

function renderProjects(projects) {
  clear("project-list");
  for (const project of projects) {
    const item = element("li");
    const button = element(
      "button",
      `${project.path} (${project.projectId})`,
      ui.project === project.projectId ? "selected" : ""
    );
    button.type = "button";
    button.addEventListener("click", async () => {
      try {
        await call("select_project", { project: project.projectId });
        ui.project = project.projectId;
        ui.run = null;
        await refreshAll();
      } catch (error) {
        showError(errorText(error));
      }
    });
    item.append(button);
    byId("project-list").append(item);
  }
}

function renderConnections(connections) {
  clear("connection-list");
  for (const connection of connections) {
    const item = element("li");
    const button = element(
      "button",
      `${connection.provider} / ${connection.model} · ${connection.authMethod} · ${connection.status} (${connection.connectionId})`,
      ui.connection === connection.connectionId ? "selected" : ""
    );
    button.type = "button";
    button.addEventListener("click", () => {
      ui.connection = connection.connectionId;
      ui.connectionAuth = connection.authMethod;
      renderConnections(connections);
      setText("credential-status", `Selected ${connection.connectionId} (${connection.status}).`);
      loadLoginStatus().catch((error) => showError(errorText(error)));
    });
    item.append(button);
    byId("connection-list").append(item);
  }
}

function renderSnapshot(snapshot) {
  renderRuns(snapshot.runs || []);
  renderApprovals(snapshot.pendingApprovals || []);
  setText("status-line", `Last sequence: ${snapshot.lastSequence}`);
}

function renderRuns(runs) {
  clear("run-list");
  for (const run of runs) {
    const item = element("li");
    const button = element(
      "button",
      `${run.runId} · ${run.state} · ${run.instructions.slice(0, 80)}`,
      ui.run === run.runId ? "selected" : ""
    );
    button.type = "button";
    button.addEventListener("click", () => {
      ui.run = run.runId;
      renderRuns(runs);
    });
    item.append(button);
    byId("run-list").append(item);
  }
  if (!ui.run && runs.length > 0) {
    ui.run = runs[runs.length - 1].runId;
  }
}

function renderApprovals(approvals) {
  clear("approval-list");
  for (const approval of approvals) {
    const item = element("li");
    const operation = approval.operation || {};
    item.append(
      element(
        "div",
        `${operation.tool || "tool"} ${operation.operationId || ""} · run ${approval.runId} · ` +
          `reason: ${approval.reason}${approval.reusable ? "" : " · requires re-evaluation"}`
      )
    );
    const details = element("pre");
    details.textContent = JSON.stringify(
      {
        arguments: operation.arguments,
        cwd: operation.cwd,
        policyVersion: operation.policyVersion,
        permissionMode: operation.permissionMode,
      },
      null,
      2
    );
    item.append(details);

    const row = element("div", null, "row");
    const approveButton = element("button", "Approve and execute once");
    approveButton.type = "button";
    approveButton.addEventListener("click", async () => {
      try {
        await call("approve", {
          project: approval.projectId,
          operation: operation.operationId,
        });
        await refreshAll();
      } catch (error) {
        showError(errorText(error));
      }
    });
    const denyButton = element("button", "Deny");
    denyButton.type = "button";
    denyButton.addEventListener("click", async () => {
      try {
        await call("deny", {
          project: approval.projectId,
          operation: operation.operationId,
        });
        await refreshAll();
      } catch (error) {
        showError(errorText(error));
      }
    });
    row.append(approveButton, denyButton);
    item.append(row);
    byId("approval-list").append(item);
  }
}

function renderHistory(events) {
  clear("history-list");
  const ordered = (events || []).slice().sort((left, right) => right.sequence - left.sequence);
  for (const event of ordered) {
    const item = element("li");
    item.append(element("div", `#${event.sequence} ${event.kind} · ${event.runId}`));
    const payload = element("pre");
    payload.textContent = JSON.stringify(event.payload, null, 2);
    item.append(payload);
    byId("history-list").append(item);
  }
}

function renderProjectSummary(project) {
  const capabilities = JSON.stringify(project.capabilities || {}, null, 2);
  const toolchain = JSON.stringify(project.toolchain || {}, null, 2);
  setText(
    "project-summary",
    `${project.path}\nConnections: ${(project.connections || []).length}\n` +
      `Capabilities: ${capabilities}\nToolchain: ${toolchain}`
  );
}

async function loadProjectView() {
  if (!ui.project) {
    setText("project-summary", "No project is open.");
    return;
  }
  const project = await call("project_view", { project: ui.project });
  renderProjectSummary(project);
}

async function loadSnapshot() {
  if (!ui.project) {
    clear("run-list");
    clear("approval-list");
    setText("status-line", "No project is open.");
    return;
  }
  const snapshot = await call("snapshot", { project: ui.project });
  renderSnapshot(snapshot);
}

async function loadHistory() {
  if (!ui.project) {
    clear("history-list");
    return;
  }
  const limit = Number(byId("history-limit").value) || 100;
  const batch = await call("history", { project: ui.project, limit });
  renderHistory(batch.events || []);
}

async function loadLoginStatus() {
  if (!ui.connection || ui.connectionAuth !== "chatgpt_login") {
    setText("login-status", "Select a ChatGPT-login connection to inspect login state.");
    return;
  }
  const status = await call("chatgpt_login_status", { connection: ui.connection });
  setText(
    "login-status",
    `Terms: ${status.terms} · state: ${status.state} · pending: ${status.pending} · ` +
      `token exchange: ${status.transport}` +
      (status.accountSubject ? ` · account: ${status.accountSubject}` : "")
  );
}

async function pollProject() {
  if (!ui.project) {
    return;
  }
  try {
    const result = await call("poll_project", { project: ui.project });
    renderSnapshot(result.snapshot);
    await loadHistory();
  } catch (error) {
    showError(errorText(error));
  }
}

async function refreshAll() {
  showError("");
  await frontendState();
  await loadProjectView();
  await loadSnapshot();
  await loadHistory();
  await loadLoginStatus();
}

async function refreshQuit() {
  try {
    const state = await call("quit_state");
    const actions = byId("quit-actions");
    let text = `Stage: ${state.stage}`;
    if (state.remainingMs !== null && state.remainingMs !== undefined) {
      text += ` · grace remaining: ${state.remainingMs} ms`;
    }
    if (state.stopFinished) {
      text += ` · stops finished: ${state.allInactive} · save confirmed: ${state.saveSucceeded}`;
    }
    if ((state.unconfirmedRuns || []).length > 0) {
      text += ` · unconfirmed runs: ${state.unconfirmedRuns.length}`;
    }
    if (state.detail) {
      text += ` · ${state.detail}`;
    }
    setText("quit-status", text);
    actions.hidden = !(state.canKeepWaiting || state.canForceQuit);
    byId("quit-keep-waiting").hidden = !state.canKeepWaiting;
    byId("quit-force").hidden = !state.canForceQuit;
  } catch (error) {
    setText("quit-status", `Quit state unavailable: ${errorText(error)}`);
  }
}

function scheduleQuitPoll() {
  window.setTimeout(async () => {
    await refreshQuit();
    scheduleQuitPoll();
  }, 500);
}

function schedulePoll() {
  window.setTimeout(async () => {
    await pollProject();
    schedulePoll();
  }, 2000);
}

function bind() {
  byId("open-project").addEventListener("click", async () => {
    try {
      const path = byId("project-path").value;
      const project = await call("open_project", { path });
      ui.project = project.projectId;
      ui.run = null;
      await refreshAll();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("connection-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const provider = byId("provider").value;
      const authMethod = byId("auth-method").value;
      const endpointValue = byId("endpoint").value.trim();
      const connection = await call("add_connection", {
        provider,
        model: byId("model").value,
        authMethod,
        endpoint: endpointValue.length > 0 ? endpointValue : null,
        insecureHttpAcknowledged: byId("insecure-http").checked,
      });
      ui.connection = connection.connectionId;
      ui.connectionAuth = connection.authMethod;
      await frontendState();
      await loadLoginStatus();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("save-api-key").addEventListener("click", async () => {
    const input = byId("api-key");
    try {
      if (!ui.connection) {
        throw new Error("select a connection first");
      }
      await call("save_api_key", {
        connection: ui.connection,
        apiKey: input.value,
      });
      setText(
        "credential-status",
        "API key stored in the macOS Keychain. It cannot be read back from this screen."
      );
      await frontendState();
    } catch (error) {
      showError(errorText(error));
    } finally {
      // The secret never stays in the DOM or in browser storage.
      input.value = "";
    }
  });

  byId("start-login").addEventListener("click", async () => {
    try {
      if (!ui.connection) {
        throw new Error("select a ChatGPT-login connection first");
      }
      await call("start_chatgpt_login", { connection: ui.connection });
      await loadLoginStatus();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("cancel-login").addEventListener("click", async () => {
    try {
      if (!ui.connection) {
        throw new Error("select a ChatGPT-login connection first");
      }
      await call("cancel_chatgpt_login", { connection: ui.connection });
      await loadLoginStatus();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("start-run").addEventListener("click", async () => {
    try {
      if (!ui.project) {
        throw new Error("open a project first");
      }
      if (!ui.connection) {
        throw new Error("select a connection first");
      }
      const run = await call("start_run", {
        project: ui.project,
        connection: ui.connection,
        instructions: byId("instructions").value,
      });
      ui.run = run.runId;
      await refreshAll();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("stop-run").addEventListener("click", async () => {
    try {
      if (!ui.project || !ui.run) {
        throw new Error("select a run first");
      }
      await call("stop_run", { project: ui.project, run: ui.run });
      await refreshAll();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("resume-run").addEventListener("click", async () => {
    try {
      if (!ui.project || !ui.run) {
        throw new Error("select a run first");
      }
      await call("resume_run", { project: ui.project, run: ui.run });
      await refreshAll();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("refresh").addEventListener("click", async () => {
    try {
      await refreshAll();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("quit-app").addEventListener("click", async () => {
    try {
      await call("quit_app");
      await refreshQuit();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("quit-keep-waiting").addEventListener("click", async () => {
    try {
      await call("quit_choice", { choice: "keep_waiting" });
      await refreshQuit();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("quit-force").addEventListener("click", async () => {
    try {
      await call("quit_choice", { choice: "force_quit" });
      await refreshQuit();
    } catch (error) {
      showError(errorText(error));
    }
  });

  // The paste event is allowed so a human can paste a key, but the UI never
  // reads it back after submission.
  byId("api-key").addEventListener("input", () => {
    setText("credential-status", "Typing a key; it is sent only when you press Save key.");
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  bind();
  if (!invoke) {
    showError("Tauri IPC is unavailable in this document.");
    return;
  }
  try {
    await refreshAll();
    await refreshQuit();
    await call("ui_ready");
    document.title = "herness ready";
    schedulePoll();
    scheduleQuitPoll();
  } catch (error) {
    document.title = `herness error: ${errorText(error)}`;
    showError(errorText(error));
  }
});
