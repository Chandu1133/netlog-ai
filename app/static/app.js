const REFRESH_INTERVAL_MS = 30000;

let telemetryChart = null;
let selectedIncidentId = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatTime(isoStr) {
  if (!isoStr) return "-";
  const dt = new Date(isoStr.endsWith("Z") ? isoStr : `${isoStr}Z`);
  if (Number.isNaN(dt.getTime())) return isoStr;
  return dt.toLocaleString();
}

function severityBadge(severity) {
  const sev = (severity || "low").toLowerCase();
  return `<span class="badge badge-${escapeHtml(sev)}">${escapeHtml(sev)}</span>`;
}

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} for ${url}`);
  }
  return res.json();
}

async function loadHealth() {
  const pill = document.getElementById("health-pill");
  try {
    const data = await fetchJson("/health");
    pill.textContent = `Status: ${data.status.toUpperCase()} · DB: ${data.database} · LLM: ${data.llm_provider}`;
  } catch (_err) {
    pill.textContent = "Status: OFFLINE";
  }
}

function renderChart(timeseries) {
  const canvas = document.getElementById("telemetryChart");
  if (!canvas || typeof Chart === "undefined") return;

  const labels = timeseries.map((pt) => {
    const dt = new Date(pt.timestamp.endsWith("Z") ? pt.timestamp : `${pt.timestamp}Z`);
    return Number.isNaN(dt.getTime())
      ? pt.timestamp
      : dt.toISOString().slice(11, 16);
  });

  const errorRates = timeseries.map((pt) => Number((pt.error_rate * 100).toFixed(2)));
  const p95Latencies = timeseries.map((pt) => pt.p95_latency_ms ?? null);
  const anomalyMarkers = timeseries.map((pt) =>
    pt.anomaly_count > 0 ? Number((pt.error_rate * 100).toFixed(2)) : null
  );
  const latencyAnomalyMarkers = timeseries.map((pt) =>
    pt.anomaly_count > 0 && pt.p95_latency_ms !== null ? pt.p95_latency_ms : null
  );

  if (telemetryChart) {
    telemetryChart.destroy();
  }

  telemetryChart = new Chart(canvas.getContext("2d"), {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Error Rate (%)",
          data: errorRates,
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56, 189, 248, 0.14)",
          fill: true,
          tension: 0.25,
          yAxisID: "yError",
          pointRadius: 2,
        },
        {
          label: "p95 Latency (ms)",
          data: p95Latencies,
          borderColor: "#fbbf24",
          backgroundColor: "rgba(251, 191, 36, 0.1)",
          tension: 0.25,
          yAxisID: "yLatency",
          pointRadius: 2,
        },
        {
          label: "Anomaly (Error)",
          data: anomalyMarkers,
          borderColor: "#f87171",
          backgroundColor: "#f87171",
          showLine: false,
          pointRadius: 6,
          pointHoverRadius: 8,
          yAxisID: "yError",
        },
        {
          label: "Anomaly (Latency)",
          data: latencyAnomalyMarkers,
          borderColor: "#ef4444",
          backgroundColor: "#ef4444",
          pointStyle: "triangle",
          showLine: false,
          pointRadius: 7,
          pointHoverRadius: 9,
          yAxisID: "yLatency",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { labels: { color: "#cbd5e1" } },
      },
      scales: {
        x: {
          ticks: { color: "#93a4c1", maxTicksLimit: 14 },
          grid: { color: "rgba(148, 163, 184, 0.12)" },
        },
        yError: {
          type: "linear",
          position: "left",
          min: 0,
          max: 100,
          title: { display: true, text: "Error Rate (%)", color: "#38bdf8" },
          ticks: { color: "#93a4c1" },
          grid: { color: "rgba(148, 163, 184, 0.12)" },
        },
        yLatency: {
          type: "linear",
          position: "right",
          min: 0,
          title: { display: true, text: "p95 Latency (ms)", color: "#fbbf24" },
          ticks: { color: "#93a4c1" },
          grid: { drawOnChartArea: false },
        },
      },
    },
  });
}

async function loadStats() {
  const host = document.getElementById("host-filter").value.trim();
  const params = new URLSearchParams();
  if (host) params.set("host", host);

  const stats = await fetchJson(`/stats?${params.toString()}`);
  document.getElementById("kpi-logs").textContent = stats.total_logs.toLocaleString();
  document.getElementById("kpi-anomalies").textContent = stats.total_anomalies.toLocaleString();
  document.getElementById("kpi-incidents").textContent = stats.total_incidents.toLocaleString();
  document.getElementById("kpi-high").textContent = (
    stats.incidents_by_severity.high || 0
  ).toLocaleString();

  renderChart(stats.timeseries || []);
}

async function loadIncidentDetail(incidentId) {
  selectedIncidentId = incidentId;
  const container = document.getElementById("incident-detail");
  const providerPill = document.getElementById("detail-provider");

  try {
    const inc = await fetchJson(`/incidents/${incidentId}`);
    providerPill.textContent = `LLM: ${inc.llm_provider}${inc.used_fallback ? " (fallback)" : ""} · Confidence: ${Math.round(inc.confidence * 100)}%`;

    const anomalyBlocks = (inc.anomalies || [])
      .map((a) => {
        const samples = (a.sample_lines || [])
          .map((line) => `<li>${escapeHtml(line)}</li>`)
          .join("");
        return `
          <div class="detail-section">
            <h3>${escapeHtml(a.anomaly_type)} (${escapeHtml(a.detector)})</h3>
            <div class="incident-meta">
              <span>Severity: ${severityBadge(a.severity)}</span>
              <span>Window: ${escapeHtml(formatTime(a.window_start))} – ${escapeHtml(formatTime(a.window_end))}</span>
              <span>Score: ${escapeHtml(a.score ?? "-")}</span>
            </div>
            ${samples ? `<ul class="sample-list">${samples}</ul>` : ""}
          </div>
        `;
      })
      .join("");

    container.innerHTML = `
      <div class="detail-section">
        <div class="incident-top">
          <div class="incident-title">${escapeHtml(inc.title)}</div>
          ${severityBadge(inc.severity)}
        </div>
        <div class="incident-meta">
          <span>Host: <strong>${escapeHtml(inc.host || "-")}</strong></span>
          <span>Service: <strong>${escapeHtml(inc.service || "-")}</strong></span>
          <span>Status: <strong>${escapeHtml(inc.status)}</strong></span>
          <span>Window: ${escapeHtml(formatTime(inc.window_start))} – ${escapeHtml(formatTime(inc.window_end))}</span>
        </div>
      </div>
      <div class="detail-section">
        <h3>AI Summary</h3>
        <p>${escapeHtml(inc.summary)}</p>
      </div>
      <div class="detail-section">
        <h3>Likely Root Cause</h3>
        <p>${escapeHtml(inc.likely_root_cause)}</p>
      </div>
      <div class="detail-section">
        <h3>Suggested Fix</h3>
        <p>${escapeHtml(inc.suggested_fix)}</p>
      </div>
      <div class="detail-section">
        <h3>Redacted Evidence</h3>
        <pre class="code-block">${escapeHtml(JSON.stringify(inc.evidence, null, 2))}</pre>
      </div>
      ${anomalyBlocks}
    `;

    document.querySelectorAll(".incident-item").forEach((el) => {
      el.classList.toggle("active", Number(el.dataset.id) === incidentId);
    });
  } catch (err) {
    container.innerHTML = `<div class="empty-state">Failed to load incident #${escapeHtml(incidentId)}: ${escapeHtml(err.message)}</div>`;
  }
}

async function loadIncidents() {
  const severity = document.getElementById("severity-filter").value;
  const host = document.getElementById("host-filter").value.trim();
  const params = new URLSearchParams({ limit: "50", offset: "0" });
  if (severity) params.set("severity", severity);
  if (host) params.set("host", host);

  const listEl = document.getElementById("incident-list");
  const data = await fetchJson(`/incidents?${params.toString()}`);

  if (!data.items || data.items.length === 0) {
    listEl.innerHTML =
      '<div class="empty-state">No incidents found. Upload logs or adjust filters.</div>';
    return;
  }

  listEl.innerHTML = data.items
    .map(
      (inc) => `
      <div class="incident-item ${inc.id === selectedIncidentId ? "active" : ""}" data-id="${inc.id}">
        <div class="incident-top">
          <span class="incident-title">${escapeHtml(inc.title)}</span>
          ${severityBadge(inc.severity)}
        </div>
        <div class="incident-meta">
          <span>Host: ${escapeHtml(inc.host || "-")}</span>
          <span>Service: ${escapeHtml(inc.service || "-")}</span>
          <span>Confidence: ${Math.round(inc.confidence * 100)}%</span>
          <span>${escapeHtml(formatTime(inc.window_start))}</span>
        </div>
      </div>
    `
    )
    .join("");

  listEl.querySelectorAll(".incident-item").forEach((el) => {
    el.addEventListener("click", () => loadIncidentDetail(Number(el.dataset.id)));
  });

  if (selectedIncidentId === null || !data.items.some((i) => i.id === selectedIncidentId)) {
    await loadIncidentDetail(data.items[0].id);
  }
}

async function refreshAll() {
  const refreshPill = document.getElementById("refresh-pill");
  try {
    await Promise.all([loadHealth(), loadStats(), loadIncidents()]);
    refreshPill.textContent = `Updated ${new Date().toLocaleTimeString()} · Auto 30s`;
  } catch (err) {
    refreshPill.textContent = `Refresh error: ${err.message}`;
  }
}

async function handleUpload(event) {
  event.preventDefault();
  const statusEl = document.getElementById("upload-status");
  const apiKey = document.getElementById("api-key-input").value.trim();
  const fileInput = document.getElementById("log-file-input");

  if (!fileInput.files || fileInput.files.length === 0) {
    statusEl.textContent = "Please choose a .log or .txt file.";
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  statusEl.textContent = "Uploading & analyzing…";

  try {
    const res = await fetch("/logs/upload?run_analysis=true", {
      method: "POST",
      headers: { "X-API-Key": apiKey },
      body: formData,
    });
    const body = await res.json();
    if (!res.ok) {
      statusEl.textContent = `Error (${res.status}): ${body.detail || "Upload failed"}`;
      return;
    }
    statusEl.textContent = `Ingested ${body.ingested_count} lines (${body.bad_line_count} bad) · ${body.anomalies_detected} anomalies · ${body.incidents_created} incidents`;
    await refreshAll();
  } catch (err) {
    statusEl.textContent = `Upload error: ${err.message}`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("refresh-btn").addEventListener("click", refreshAll);
  document.getElementById("severity-filter").addEventListener("change", refreshAll);
  document.getElementById("host-filter").addEventListener("input", () => {
    clearTimeout(window._hostFilterTimer);
    window._hostFilterTimer = setTimeout(refreshAll, 300);
  });
  document.getElementById("upload-form").addEventListener("submit", handleUpload);

  refreshAll();
  setInterval(refreshAll, REFRESH_INTERVAL_MS);
});
