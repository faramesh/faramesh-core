const healthPill = document.getElementById("health-pill");
const healthText = document.getElementById("health-text");
const pendingCount = document.getElementById("pending-count");
const pendingList = document.getElementById("pending-list");
const actionsCount = document.getElementById("actions-count");
const actionsBody = document.getElementById("actions-body");
const selectedCall = document.getElementById("selected-call");
const timeline = document.getElementById("timeline");
const actionMeta = document.getElementById("action-meta");
const actionTool = document.getElementById("action-tool");
const actionOperation = document.getElementById("action-operation");
const actionAgent = document.getElementById("action-agent");
const actionState = document.getElementById("action-state");
const actionControls = document.getElementById("action-controls");
const integrityOutput = document.getElementById("integrity-output");
const verifyButton = document.getElementById("verify-integrity");

let selectedCallId = "";
let actionRows = [];

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function requestJSON(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail ? JSON.stringify(payload.detail) : response.statusText);
  }
  return payload;
}

function splitToolFields(item) {
  const rawToolId = String(item.tool_id || "");
  let toolName = String(item.tool_name || "");
  let operation = String(item.operation || "");

  if ((!toolName || !operation) && rawToolId.includes("/")) {
    const idx = rawToolId.lastIndexOf("/");
    if (!toolName) {
      toolName = rawToolId.slice(0, idx);
    }
    if (!operation) {
      operation = rawToolId.slice(idx + 1);
    }
  }

  return {
    toolName: toolName || rawToolId || "-",
    operation: operation || "-",
  };
}

function shortCallId(callId) {
  const text = String(callId || "");
  if (!text) {
    return "-";
  }
  if (text.length <= 44) {
    return text;
  }
  return `${text.slice(0, 24)}...${text.slice(-12)}`;
}

function canResolveAction(action) {
  return String(action?.state || "") === "pending" && Boolean(action?.defer_token);
}

async function resolveAction(action, approve) {
  if (!action || !canResolveAction(action)) {
    return;
  }
  const endpoint = approve ? "approve" : "deny";
  const defaultReason = approve ? "approved via visibility UI" : "denied via visibility UI";
  const reason = prompt(`Optional reason for ${endpoint}:`, defaultReason) || "";

  try {
    await requestJSON(`/actions/${encodeURIComponent(action.call_id)}/${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    await refreshAll();
  } catch (error) {
    alert(`Failed to ${endpoint} action: ${error}`);
  }
}

function setHealthPill(kind, label) {
  healthPill.className = `pill ${kind}`;
  healthPill.textContent = label;
}

async function refreshHealth() {
  try {
    const payload = await requestJSON("/healthz");
    const streams = payload.streams || {};
    const streamText = `callback:${streams.callback ? "up" : "down"} audit:${streams.audit ? "up" : "down"}`;
    if (payload.daemon_ok) {
      setHealthPill("ok", "Healthy");
      healthText.textContent = `${streamText} | actions: ${payload.actions_tracked}`;
    } else {
      setHealthPill("warn", "Degraded");
      healthText.textContent = `${streamText} | daemon: ${payload.daemon_error || "unreachable"}`;
    }
  } catch (error) {
    setHealthPill("bad", "Offline");
    healthText.textContent = String(error);
  }
}

function renderPending(items) {
  pendingCount.textContent = String(items.length);
  if (!items.length) {
    pendingList.innerHTML = '<div class="empty">No pending defer tokens.</div>';
    return;
  }

  pendingList.innerHTML = items
    .map((item) => {
      const token = escapeHTML(item.defer_token || "");
        const fields = splitToolFields(item);
        const tool = escapeHTML(fields.toolName);
        const operation = escapeHTML(fields.operation);
      const agent = escapeHTML(item.agent_id || "unknown-agent");
      const call = escapeHTML(item.call_id || "unknown-call");
      return `
        <div class="defer-card">
          <div class="defer-meta">
              <span>${tool} / ${operation}</span>
            <span>${agent}</span>
          </div>
          <div class="defer-meta mono">
            <span>${token}</span>
            <span>${call}</span>
          </div>
          <div class="defer-actions">
            <button class="btn approve" data-action="approve" data-token="${token}">Approve</button>
            <button class="btn deny" data-action="deny" data-token="${token}">Deny</button>
          </div>
        </div>
      `;
    })
    .join("");

  pendingList.querySelectorAll("button[data-token]").forEach((button) => {
    button.addEventListener("click", async () => {
      const token = button.dataset.token;
      const action = button.dataset.action;
      if (!token || !action) {
        return;
      }
      const endpoint = action === "approve" ? "approve" : "deny";
      const reason = prompt(`Optional reason for ${endpoint}:`, `${endpoint} via visibility UI`) || "";
      try {
        await requestJSON(`/defers/${encodeURIComponent(token)}/${endpoint}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason }),
        });
        await refreshAll();
      } catch (error) {
        alert(`Failed to ${endpoint} defer token: ${error}`);
      }
    });
  });
}

function renderActions(items) {
  actionRows = Array.isArray(items) ? items : [];
  actionsCount.textContent = String(items.length);
  if (!items.length) {
      actionsBody.innerHTML = '<tr><td colspan="7" class="empty">No actions seen yet.</td></tr>';
    return;
  }

  actionsBody.innerHTML = items
    .map((item) => {
      const callId = escapeHTML(item.call_id || "");
      const callShort = escapeHTML(shortCallId(item.call_id || ""));
      const state = escapeHTML(item.state || "unknown");
      const reasonCode = escapeHTML(item.reason_code || "-");
      const updatedAt = escapeHTML(item.updated_at || "-");
      const fields = splitToolFields(item);
      const toolCell = `${escapeHTML(fields.toolName)} <span class="mono">/ ${escapeHTML(fields.operation)}</span>`;
      const canResolve = canResolveAction(item);
      const control = canResolve
        ? `
          <div class="defer-actions">
            <button class="btn approve" data-call-id="${callId}" data-action="approve">Approve</button>
            <button class="btn deny" data-call-id="${callId}" data-action="deny">Deny</button>
          </div>
        `
        : '<span class="empty">Auto</span>';
      const selectedClass = (item.call_id || "") === selectedCallId ? " selected" : "";
      return `
          <tr data-call-id="${callId}" class="${selectedClass}">
            <td class="mono" title="${callId}">${callShort}</td>
          <td>${escapeHTML(item.agent_id || "-")}</td>
            <td>${toolCell}</td>
          <td><span class="state ${state}">${state}</span></td>
          <td>${reasonCode}</td>
          <td class="mono">${updatedAt}</td>
            <td>${control}</td>
        </tr>
      `;
    })
    .join("");

  actionsBody.querySelectorAll("tr[data-call-id]").forEach((row) => {
    row.addEventListener("click", async () => {
      selectedCallId = row.dataset.callId || "";
      await refreshSelectedTimeline();
    });
  });

  if (!selectedCallId && items.length) {
    selectedCallId = items[0].call_id;
  }

  actionsBody.querySelectorAll("button[data-call-id][data-action]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.stopPropagation();
      const callId = button.dataset.callId || "";
      const actionType = button.dataset.action || "";
      if (!callId || !actionType) {
        return;
      }
      const action = actionRows.find((item) => (item.call_id || "") === callId);
      if (!action) {
        return;
      }
      await resolveAction(action, actionType === "approve");
    });
  });
}

function renderActionDetail(action) {
  if (!action) {
    actionMeta.textContent = "Select an action row to inspect details.";
    actionTool.textContent = "-";
    actionOperation.textContent = "-";
    actionAgent.textContent = "-";
    actionState.textContent = "-";
    actionControls.innerHTML = '<span class="empty">No manual action available.</span>';
    return;
  }

  const fields = splitToolFields(action);
  actionMeta.textContent = `${action.reason_code || ""} ${action.reason ? `| ${action.reason}` : ""}`.trim() || "No reason details";
  actionTool.textContent = fields.toolName;
  actionOperation.textContent = fields.operation;
  actionAgent.textContent = String(action.agent_id || "-");
  actionState.textContent = String(action.state || "-");

  if (!canResolveAction(action)) {
    actionControls.innerHTML =
      '<span class="empty">Approve/Deny is only available for DEFER actions (state=pending with a defer token).</span>';
    return;
  }

  actionControls.innerHTML = `
    <button class="btn approve" id="action-approve-btn">Approve</button>
    <button class="btn deny" id="action-deny-btn">Deny</button>
  `;
  const approveBtn = document.getElementById("action-approve-btn");
  const denyBtn = document.getElementById("action-deny-btn");
  approveBtn?.addEventListener("click", async () => {
    await resolveAction(action, true);
  });
  denyBtn?.addEventListener("click", async () => {
    await resolveAction(action, false);
  });
}

function renderTimeline(action) {
  if (!action) {
    selectedCall.textContent = "none";
    timeline.innerHTML = '<div class="empty">Pick an action row to inspect timeline details.</div>';
    renderActionDetail(null);
    return;
  }

  selectedCall.textContent = action.call_id;
  renderActionDetail(action);
  const events = Array.isArray(action.timeline) ? action.timeline : [];
  if (!events.length) {
    timeline.innerHTML = '<div class="empty">No timeline events available.</div>';
    return;
  }

  timeline.innerHTML = events
    .map((item) => {
      const reasonText = item.reason ? `<div>${escapeHTML(item.reason)}</div>` : "";
      const dprText = item.record_id
        ? `<div class="mono">record:${escapeHTML(item.record_id)} hash:${escapeHTML(item.record_hash || "-")}</div>`
        : "";
      return `
        <div class="timeline-item">
          <div class="timeline-head">
            <span>${escapeHTML(item.state || "unknown")} via ${escapeHTML(item.source || "stream")}</span>
            <span class="mono">${escapeHTML(item.timestamp || "")}</span>
          </div>
          <div class="timeline-body">
            <div>${escapeHTML(item.effect || "")}${item.reason_code ? ` | ${escapeHTML(item.reason_code)}` : ""}</div>
            ${reasonText}
            ${dprText}
          </div>
        </div>
      `;
    })
    .join("");
}

async function refreshSelectedTimeline() {
  if (!selectedCallId) {
    renderTimeline(null);
    return;
  }
  try {
    const action = await requestJSON(`/actions/${encodeURIComponent(selectedCallId)}`);
    renderTimeline(action);
  } catch {
    const fallback = actionRows.find((item) => (item.call_id || "") === selectedCallId) || null;
    renderTimeline(fallback);
  }
}

async function refreshAll() {
  await refreshHealth();
  const [pending, actions] = await Promise.all([requestJSON("/defers/pending"), requestJSON("/actions?limit=250")]);
  renderPending(Array.isArray(pending.items) ? pending.items : []);
  renderActions(Array.isArray(actions.items) ? actions.items : []);
  await refreshSelectedTimeline();
}

verifyButton.addEventListener("click", async () => {
  integrityOutput.textContent = "Running integrity verification...";
  try {
    const payload = await requestJSON("/integrity/verify");
    integrityOutput.textContent = JSON.stringify(payload, null, 2);
  } catch (error) {
    integrityOutput.textContent = String(error);
  }
});

refreshAll().catch((error) => {
  healthText.textContent = String(error);
});
setInterval(() => {
  refreshAll().catch((error) => {
    healthText.textContent = String(error);
  });
}, 3000);
