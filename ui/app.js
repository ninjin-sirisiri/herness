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
  connections: [],
  supervision: [],
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
  ui.connections = state.connections || [];
  renderProjects(state.projects || []);
  renderConnections(ui.connections);
  renderReconciliation(state.reconciliation);
  setText(
    "policy-line",
    `Permission mode: ${state.permissionMode} (policy ${state.policyVersion}) · ` +
      `Automatic decision capability: ${state.automaticModeAvailable ? "available" : "unavailable"} — ` +
      `${state.automaticModeReason}`
  );
  if (byId("automatic-warning")) {
    setText(
      "automatic-warning",
      state.automaticModeAvailable
        ? "A verified permission-evaluation profile is configured. The current policy mode still decides whether human approval is required."
        : "Automatic decision is unavailable without a verified permission-evaluation profile. Every tool operation needs an explicit human decision in this build."
    );
  }
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

function splitLines(value) {
  return String(value || "")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function reasonText(reason) {
  if (!reason) {
    return "";
  }
  if (typeof reason === "string") {
    return reason;
  }
  if (reason.kind) {
    return reason.action ? `${reason.kind} (${reason.action})` : reason.kind;
  }
  return JSON.stringify(reason);
}

function renderConnectionChoices() {
  const select = byId("sup-connection");
  const current = select.value;
  clear("sup-connection");
  for (const connection of ui.connections) {
    const option = document.createElement("option");
    option.value = connection.connectionId;
    option.textContent = `${connection.provider} / ${connection.model} (${connection.authMethod})`;
    select.append(option);
  }
  if (current) {
    select.value = current;
  }
}

function supervisionRequestId() {
  const project = ui.project || "";
  const random =
    window.crypto && window.crypto.randomUUID
      ? window.crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `command:${project}:${random}`;
}

async function loadSupervision() {
  if (!ui.project) {
    ui.supervision = [];
    clear("supervision-list");
    setText("supervision-status", "No project is open.");
    return;
  }
  const list = await call("supervision_list", { project: ui.project });
  ui.supervision = list || [];
  renderSupervision();
}

function renderSupervision() {
  clear("supervision-list");
  const list = ui.supervision || [];
  if (list.length === 0) {
    setText(
      "supervision-status",
      "No supervision target is saved for this project. Configure a completion profile and consent, then create one."
    );
    return;
  }
  setText("supervision-status", `${list.length} supervision target(s).`);
  for (const view of list) {
    const item = element("li", null, "supervision-item");
    const purpose = (view.purposes || []).find(
      (entry) => entry.purpose === view.profile.purpose
    );
    const verified = purpose && purpose.verified ? "verified" : "unverified";
    item.append(
      element(
        "div",
        `${view.state} · revision ${view.revision} · reason ${reasonText(view.reason)}`
      )
    );
    item.append(
      element(
        "div",
        `conditions v${view.conditionVersion} · target v${view.targetVersion} · ` +
          `profile ${view.profile.provider || view.profile.profileId} v${view.profile.version} ` +
          `(${verified}) · consent ${view.consent.purpose} v${view.consent.version}`
      )
    );
    item.append(
      element(
        "div",
        `unmet: ${(view.unmetConditions || []).length} · runs: ${(view.runGroup || []).length} · ` +
          `evidence: ${(view.evidence || []).length} · plan: ${view.planAvailable ? "available" : "unavailable"}`
      )
    );
    if (view.budget) {
      const budget = view.budget;
      item.append(
        element(
          "div",
          `budget ${budget.usage.activeSecondsConsumed}/${budget.activeSeconds}s · ` +
            `runs ${budget.usage.runsStarted}/${budget.additionalRuns + 1} · ` +
            `remaining ${budget.remainingActiveSeconds}s · unresolved charges ${budget.unresolvedCharges}`
        )
      );
    } else {
      item.append(element("div", "budget: unavailable"));
    }
    for (const purpose of view.purposes || []) {
      item.append(
        element(
          "div",
          `purpose ${purpose.purpose}: profile ${purpose.profileId || "unset"} ` +
            `(${purpose.verified ? "verified" : "unverified"}) · consent ${purpose.consentState} ` +
            `${purpose.consentVersion ? "v" + purpose.consentVersion : ""}`
        )
      );
    }
    for (const evidence of (view.evidence || []).slice(-5)) {
      item.append(
        element(
          "div",
          `evidence #${evidence.sequence} ${evidence.status} · ${evidence.operation} · ` +
            `${String(evidence.outcome).slice(0, 200)}`
        )
      );
    }
    for (const notification of view.notifications || []) {
      item.append(
        element(
          "div",
          `notification ${notification.state} · ${reasonText(notification.reason)} · revision ${notification.revision}`
        )
      );
    }

    const row = element("div", null, "row");
    const makeButton = (label, action) => {
      const button = element("button", label);
      button.type = "button";
      button.addEventListener("click", async () => {
        try {
          await action();
          await loadSupervision();
        } catch (error) {
          showError(errorText(error));
        }
      });
      row.append(button);
    };
    const operation = () => ({
      supervision: view.supervisionId,
      requestId: supervisionRequestId(),
      expectedRevision: view.revision,
    });
    makeButton("Start", () =>
      call("supervision_start", {
        project: ui.project,
        supervision: view.supervisionId,
        requestId: supervisionRequestId(),
        expectedRevision: view.revision,
      })
    );
    makeButton("Stop", () =>
      call("supervision_stop", operation())
    );
    makeButton("Cancel", () =>
      call("supervision_cancel", operation())
    );
    makeButton("Reassess", () =>
      call("supervision_reassess", operation())
    );
    makeButton("Resume", () =>
      call("supervision_resume", operation())
    );
    makeButton("Adopt configured profile/consent", async () => {
      await call("supervision_change", {
        project: ui.project,
        supervision: view.supervisionId,
        requestId: supervisionRequestId(),
        expectedRevision: view.revision,
        change: {
          profilePurpose: "completion",
          consentPurpose: "completion",
        },
      });
    });
    makeButton("Change budget", async () => {
      await call("supervision_change", {
        project: ui.project,
        supervision: view.supervisionId,
        requestId: supervisionRequestId(),
        expectedRevision: view.revision,
        change: {
          budget: {
            activeSeconds: Number(byId("sup-active-seconds").value) || 7200,
            additionalRuns: Number(byId("sup-additional-runs").value) || 30,
          },
        },
      });
    });
    makeButton("Change conditions", async () => {
      const command = byId("sup-check-command").value;
      await call("supervision_change", {
        project: ui.project,
        supervision: view.supervisionId,
        requestId: supervisionRequestId(),
        expectedRevision: view.revision,
        change: {
          conditionVersion: Number(view.conditionVersion) + 1,
          conditions: [
            {
              title: byId("sup-condition-title").value,
              rubric: byId("sup-condition-rubric").value,
              checks: command
                ? [
                    {
                      command,
                      description:
                        byId("sup-check-description").value || command,
                    },
                  ]
                : [],
            },
          ],
        },
      });
    });
    makeButton("Show recovery", async () => {
      const recovery = await call("supervision_recovery", {
        project: ui.project,
        supervision: view.supervisionId,
      });
      setText("supervision-detail", JSON.stringify(recovery, null, 2));
    });
    item.append(row);
    byId("supervision-list").append(item);
  }
}

async function configureSupervisionProfile() {
  if (!ui.project) {
    throw new Error("open a project first");
  }
  const connection = byId("sup-connection").value;
  if (!connection) {
    throw new Error("select a connection first");
  }
  const status = await call("supervision_profile", {
    project: ui.project,
    purpose: byId("sup-purpose").value,
    connection,
    model: byId("sup-model").value,
  });
  setText(
    "supervision-status",
    `Profile ${status.purpose}: ${status.profileId} configured as ${status.verified ? "verified" : "unverified"} (${status.provider}). A separate real acceptance step is required before any provider request.`
  );
  await loadSupervision();
}

async function grantSupervisionConsent() {
  if (!ui.project) {
    throw new Error("open a project first");
  }
  const dataKinds = [];
  for (const kind of ["text", "code", "diff", "log"]) {
    if (byId(`sup-kind-${kind}`).checked) {
      dataKinds.push(kind);
    }
  }
  const targetVersion = Number(byId("sup-consent-version").value) || 1;
  const status = await call("supervision_consent", {
    project: ui.project,
    purpose: byId("sup-purpose").value,
    action: "grant",
    origin: byId("sup-origin").value,
    dataKinds,
    targets: splitLines(byId("sup-consent-targets").value),
    targetVersion,
  });
  setText(
    "supervision-status",
    `Consent ${status.purpose}: ${status.consentState} v${status.consentVersion} (target v${status.targetScopeVersion}).`
  );
  await loadSupervision();
}

async function revokeSupervisionConsent() {
  if (!ui.project) {
    throw new Error("open a project first");
  }
  const status = await call("supervision_consent", {
    project: ui.project,
    purpose: byId("sup-purpose").value,
    action: "revoke",
  });
  setText(
    "supervision-status",
    `Consent ${status.purpose}: ${status.consentState} v${status.consentVersion}. Already sent content is not recalled.`
  );
  await loadSupervision();
}

async function createSupervision() {
  if (!ui.project) {
    throw new Error("open a project first");
  }
  const connection = byId("sup-connection").value;
  if (!connection) {
    throw new Error("select a connection first");
  }
  const title = byId("sup-condition-title").value;
  const rubric = byId("sup-condition-rubric").value;
  const command = byId("sup-check-command").value;
  const checks = command
    ? [{ command, description: byId("sup-check-description").value || command }]
    : [];
  const request = {
    project: ui.project,
    connection,
    instructions: byId("sup-instructions").value,
    conditions: [{ title, rubric, checks }],
    readSet: splitLines(byId("sup-read-set").value),
    writePaths: splitLines(byId("sup-write-paths").value),
    allowShell: byId("sup-allow-shell").checked,
    conditionVersion: 1,
    targetVersion: Number(byId("sup-consent-version").value) || 1,
    budget: {
      activeSeconds: Number(byId("sup-active-seconds").value) || 7200,
      additionalRuns: Number(byId("sup-additional-runs").value) || 30,
    },
  };
  const view = await call("supervision_create", { request });
  setText(
    "supervision-status",
    `Created ${view.supervisionId} in state ${view.state}. Start is a separate human action.`
  );
  await loadSupervision();
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
      (status.accountSubject ? ` · account: ${status.accountSubject}` : "") +
      (status.error ? ` · last attempt: ${status.error}` : "")
  );
}

async function loadChatGptModels() {
  if (!ui.connection || ui.connectionAuth !== "chatgpt_login") {
    throw new Error("select a ChatGPT-login connection first");
  }
  const models = await call("chatgpt_models", { connection: ui.connection });
  const choice = byId("model-choice");
  clear("model-list");
  choice.replaceChildren();
  for (const model of models) {
    const option = document.createElement("option");
    option.value = model.slug;
    option.textContent = `${model.displayName} (${model.slug})`;
    choice.append(option);
  }
  setText(
    "model-list",
    models.length === 0
      ? "The account catalog has no models with visibility=list."
      : models.map((model) => `${model.displayName} · ${model.slug}`).join("\n")
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
  renderConnectionChoices();
  await loadProjectView();
  await loadSnapshot();
  await loadHistory();
  await loadLoginStatus();
  await loadSupervision();
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
    const submit = event.currentTarget.querySelector("button[type='submit']");
    if (submit) {
      submit.disabled = true;
    }
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
    } finally {
      if (submit) {
        submit.disabled = false;
      }
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

  byId("list-models").addEventListener("click", async () => {
    try {
      await loadChatGptModels();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("set-model").addEventListener("click", async () => {
    try {
      const model = byId("model-choice").value;
      if (!ui.connection || !model) {
        throw new Error("list and select a ChatGPT model first");
      }
      await call("set_connection_model", { connection: ui.connection, model });
      await frontendState();
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

  byId("sup-config-profile").addEventListener("click", async () => {
    try {
      await configureSupervisionProfile();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("sup-grant-consent").addEventListener("click", async () => {
    try {
      await grantSupervisionConsent();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("sup-revoke-consent").addEventListener("click", async () => {
    try {
      await revokeSupervisionConsent();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("sup-create").addEventListener("click", async () => {
    try {
      await createSupervision();
    } catch (error) {
      showError(errorText(error));
    }
  });

  byId("sup-refresh").addEventListener("click", async () => {
    try {
      await loadSupervision();
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
