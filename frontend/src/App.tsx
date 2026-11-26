import React, { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bot,
  Cpu,
  Database,
  FileText,
  History,
  LogOut,
  Search,
  Shield,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiFetch, getToken, setToken } from "./api";
import { AgentFlowGraph } from "./components/AgentFlowGraph";
import { TierBadge } from "./components/TierBadge";

type TabId =
  | "overview"
  | "datasets"
  | "flows"
  | "alerts"
  | "incidents"
  | "investigations"
  | "threat_intel"
  | "reports"
  | "models"
  | "audit";

export default function App() {
  const [user, setUser] = useState<any>(null);
  const [email, setEmail] = useState("admin@netsentinel.io");
  const [password, setPassword] = useState("NetSentinel!2026");
  const [authError, setAuthError] = useState("");
  const [tab, setTab] = useState<TabId>("overview");
  const [toast, setToast] = useState("");

  // Operational data
  const [overview, setOverview] = useState<any>(null);
  const [datasets, setDatasets] = useState<any[]>([]);
  const [selectedDatasetId, setSelectedDatasetId] = useState("");
  const [flows, setFlows] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [shapDetail, setShapDetail] = useState<any>(null);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [activeInv, setActiveInv] = useState<any>(null);
  const [ragQuery, setRagQuery] = useState("T1046 port scan SSH brute force CVE");
  const [ragResults, setRagResults] = useState<any[]>([]);
  const [ragDocs, setRagDocs] = useState<any[]>([]);
  const [reportPreview, setReportPreview] = useState<any>(null);
  const [models, setModels] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);

  // Upload state
  const [uploadName, setUploadName] = useState("");
  const [uploadFile, setUploadFile] = useState<File | null>(null);

  const notify = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 4000);
  };

  useEffect(() => {
    if (getToken()) {
      apiFetch("/auth/me")
        .then(setUser)
        .catch(() => setToken(null));
    }
  }, []);

  const refreshData = async () => {
    if (!getToken()) return;
    try {
      const [ov, ds, al, inc, invs, docs, mods, logs] = await Promise.all([
        apiFetch("/dashboard/overview"),
        apiFetch("/datasets"),
        apiFetch("/alerts"),
        apiFetch("/incidents"),
        apiFetch("/investigations"),
        apiFetch("/threat-intel/documents"),
        apiFetch("/models"),
        apiFetch("/audit-logs"),
      ]);
      setOverview(ov);
      setDatasets(ds.items || []);
      if (!selectedDatasetId && ds.items?.length) setSelectedDatasetId(ds.items[0].dataset_id);
      setAlerts(al.items || []);
      setIncidents(inc.items || []);
      setInvestigations(invs.items || []);
      setRagDocs(docs.items || []);
      setModels(mods.items || []);
      setAuditLogs(logs.items || []);
    } catch (e: any) {
      notify(`Refresh failed: ${e.message}`);
    }
  };

  useEffect(() => {
    if (user) refreshData();
  }, [user]);

  useEffect(() => {
    if (user && selectedDatasetId) {
      apiFetch(`/datasets/${selectedDatasetId}/flows?page=1&page_size=50`)
        .then((res) => setFlows(res.items || []))
        .catch(() => setFlows([]));
    }
  }, [user, selectedDatasetId]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    try {
      const res = await apiFetch("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      setToken(res.access_token);
      setUser(res.user);
    } catch (err: any) {
      setAuthError(err.message);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadFile) return;
    const form = new FormData();
    form.append("file", uploadFile);
    form.append("name", uploadName || uploadFile.name);
    try {
      const res = await apiFetch("/datasets/upload", { method: "POST", body: form });
      notify(`Uploaded ${res.name} — extracting flows & running ML detection...`);
      setUploadName("");
      setUploadFile(null);
      await handleProcessDataset(res.dataset_id);
    } catch (err: any) {
      notify(`Upload error: ${err.message}`);
    }
  };

  const handleProcessDataset = async (datasetId: string) => {
    try {
      const res = await apiFetch(`/datasets/${datasetId}/process`, {
        method: "POST",
        body: JSON.stringify({ auto_run_detection: true }),
      });
      notify(`Processed ${res.flow_count} flows; created ${res.detection?.alerts_created ?? 0} alerts.`);
      setSelectedDatasetId(datasetId);
      await refreshData();
    } catch (err: any) {
      notify(`Processing error: ${err.message}`);
    }
  };

  const handleEscalateAlert = async (alert: any) => {
    try {
      await apiFetch("/incidents", {
        method: "POST",
        body: JSON.stringify({
          title: `Incident: ${alert.title}`,
          description: alert.summary,
          severity: alert.severity,
          alert_ids: [alert.alert_id],
        }),
      });
      notify("Alert escalated to Incident.");
      await refreshData();
      setTab("incidents");
    } catch (err: any) {
      notify(`Escalation error: ${err.message}`);
    }
  };

  const handleRunInvestigation = async (incidentId: string) => {
    try {
      const res = await apiFetch(`/incidents/${incidentId}/investigations`, { method: "POST" });
      const detail = await apiFetch(`/investigations/${res.investigation_id}`);
      setActiveInv(detail);
      notify(`Investigation completed (${detail.validation_status}).`);
      await refreshData();
      setTab("investigations");
    } catch (err: any) {
      notify(`Investigation error: ${err.message}`);
    }
  };

  const handleDecision = async (invId: string, recId: string, decision: "approved" | "rejected") => {
    try {
      await apiFetch(`/investigations/${invId}/recommendations/${recId}/approve`, {
        method: "POST",
        body: JSON.stringify({
          decision,
          rationale: `Responder ${decision} via NetSentinel SOC Dashboard.`,
        }),
      });
      const detail = await apiFetch(`/investigations/${invId}`);
      setActiveInv(detail);
      notify(`Recommendation ${decision}.`);
    } catch (err: any) {
      notify(`Approval error: ${err.message}`);
    }
  };

  const handleRagSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch("/threat-intel/search", {
        method: "POST",
        body: JSON.stringify({ query: ragQuery, top_k: 5, use_reranker: true }),
      });
      setRagResults(res.results || []);
    } catch (err: any) {
      notify(`Search error: ${err.message}`);
    }
  };

  const handleGenerateReport = async (incidentId: string) => {
    try {
      const res = await apiFetch(`/incidents/${incidentId}/reports`, {
        method: "POST",
        body: JSON.stringify({ format: "markdown", anonymize_ips: false }),
      });
      setReportPreview(res);
      setTab("reports");
      notify(`Generated report ${res.report_id}`);
    } catch (err: any) {
      notify(`Report error: ${err.message}`);
    }
  };

  if (!user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 p-6">
        <form
          onSubmit={handleLogin}
          className="w-full max-w-md space-y-5 rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-2xl"
        >
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-sky-400" />
            <div>
              <h1 className="text-xl font-bold text-white">NetSentinel AI</h1>
              <p className="text-xs text-slate-400">Network Threat Detection & Autonomous SOC</p>
            </div>
          </div>
          {authError && (
            <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-300">
              {authError}
            </div>
          )}
          <div className="space-y-3">
            <label className="block text-xs text-slate-300">
              Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              />
            </label>
            <label className="block text-xs text-slate-300">
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              />
            </label>
          </div>
          <button
            type="submit"
            className="w-full rounded-lg bg-sky-500 py-2.5 text-sm font-semibold text-slate-950 hover:bg-sky-400"
          >
            Sign In to SOC Workspace
          </button>
        </form>
      </div>
    );
  }

  const navItems: { id: TabId; label: string; icon: React.ReactNode }[] = [
    { id: "overview", label: "Dashboard Overview", icon: <Activity className="h-4 w-4" /> },
    { id: "datasets", label: "Dataset Management", icon: <Upload className="h-4 w-4" /> },
    { id: "flows", label: "Traffic Analytics", icon: <Database className="h-4 w-4" /> },
    { id: "alerts", label: "Alert Management", icon: <AlertTriangle className="h-4 w-4" /> },
    { id: "incidents", label: "Incident Management", icon: <ShieldAlert className="h-4 w-4" /> },
    { id: "investigations", label: "Investigation Workspace", icon: <Bot className="h-4 w-4" /> },
    { id: "threat_intel", label: "Threat Intel (RAG)", icon: <Search className="h-4 w-4" /> },
    { id: "reports", label: "Incident Reports", icon: <FileText className="h-4 w-4" /> },
    { id: "models", label: "Model Analytics", icon: <Cpu className="h-4 w-4" /> },
    { id: "audit", label: "Audit Logs", icon: <History className="h-4 w-4" /> },
  ];

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100">
      <aside className="flex w-64 flex-col border-r border-slate-800 bg-slate-900/70 p-4">
        <div className="mb-6 flex items-center gap-2.5 px-2">
          <Shield className="h-6 w-6 text-sky-400" />
          <div>
            <div className="text-sm font-bold text-white">NetSentinel AI</div>
            <div className="text-[11px] text-slate-400">{user.email}</div>
          </div>
        </div>
        <nav className="flex-1 space-y-1">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setTab(item.id)}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition ${
                tab === item.id
                  ? "bg-sky-500/15 text-sky-300"
                  : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </nav>
        <button
          onClick={() => {
            setToken(null);
            setUser(null);
          }}
          className="mt-4 flex items-center gap-2 rounded-lg border border-slate-800 px-3 py-2 text-xs text-slate-400 hover:text-white"
        >
          <LogOut className="h-4 w-4" /> Sign Out
        </button>
      </aside>

      <main className="flex-1 overflow-y-auto p-6">
        {toast && (
          <div className="mb-4 rounded-lg border border-sky-500/40 bg-sky-500/10 px-4 py-2 text-xs text-sky-200">
            {toast}
          </div>
        )}

        {tab === "overview" && (
          <div className="space-y-6">
            <h2 className="text-xl font-bold">Security Operations Overview</h2>
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
              {[
                ["Datasets", overview?.kpis?.datasets_count ?? 0],
                ["Network Flows", overview?.kpis?.flows_count ?? 0],
                ["Open Alerts", overview?.kpis?.open_alerts ?? 0],
                ["Incidents", overview?.kpis?.incidents_count ?? 0],
                ["Investigations", overview?.kpis?.investigations_count ?? 0],
              ].map(([label, val]) => (
                <div key={String(label)} className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                  <div className="text-xs text-slate-400">{label}</div>
                  <div className="mt-1 text-2xl font-bold text-white">{val}</div>
                </div>
              ))}
            </div>
            <div className="grid gap-6 lg:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                <h3 className="mb-3 text-sm font-semibold">Protocol Distribution</h3>
                <div className="h-56">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={overview?.protocol_distribution || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="protocol" stroke="#94a3b8" />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip />
                      <Bar dataKey="count" fill="#38bdf8" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                <h3 className="mb-3 text-sm font-semibold">Alert Classification Tiers</h3>
                <div className="h-56">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={overview?.alert_tier_distribution || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="tier" stroke="#94a3b8" />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip />
                      <Bar dataKey="count" fill="#f97316" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === "datasets" && (
          <div className="space-y-6">
            <h2 className="text-xl font-bold">Dataset Management (PCAP Ingestion)</h2>
            <form
              onSubmit={handleUpload}
              className="flex flex-wrap items-end gap-3 rounded-xl border border-slate-800 bg-slate-900 p-4"
            >
              <label className="text-xs text-slate-300">
                Dataset Name
                <input
                  value={uploadName}
                  onChange={(e) => setUploadName(e.target.value)}
                  placeholder="edge-capture.pcap"
                  className="mt-1 block rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm"
                />
              </label>
              <label className="text-xs text-slate-300">
                PCAP / PCAPNG File
                <input
                  type="file"
                  accept=".pcap,.pcapng"
                  onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                  className="mt-1 block text-xs text-slate-300"
                />
              </label>
              <button
                type="submit"
                className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
              >
                Upload PCAP
              </button>
            </form>
            <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="p-3">Name</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Packets / Flows</th>
                    <th className="p-3">Size</th>
                    <th className="p-3">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {datasets.map((d) => (
                    <tr key={d.dataset_id}>
                      <td className="p-3 font-medium text-white">{d.name}</td>
                      <td className="p-3">{d.status}</td>
                      <td className="p-3">
                        {d.packet_count} / {d.flow_count}
                      </td>
                      <td className="p-3">{d.file_size_bytes} B</td>
                      <td className="p-3">
                        <button
                          onClick={() => handleProcessDataset(d.dataset_id)}
                          className="rounded bg-sky-500/20 px-2.5 py-1 text-sky-300 hover:bg-sky-500/30"
                        >
                          Extract & Detect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === "flows" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-bold">Traffic Analytics & Flow Explorer</h2>
              <select
                value={selectedDatasetId}
                onChange={(e) => setSelectedDatasetId(e.target.value)}
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs"
              >
                {datasets.map((d) => (
                  <option key={d.dataset_id} value={d.dataset_id}>
                    {d.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="p-3">Source</th>
                    <th className="p-3">Destination</th>
                    <th className="p-3">Proto</th>
                    <th className="p-3">Bytes</th>
                    <th className="p-3">Anomaly Score</th>
                    <th className="p-3">Tier</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {flows.map((f) => (
                    <tr key={f.flow_id}>
                      <td className="p-3 font-mono">{f.src_ip}:{f.src_port}</td>
                      <td className="p-3 font-mono">{f.dst_ip}:{f.dst_port}</td>
                      <td className="p-3">{f.protocol}</td>
                      <td className="p-3">{f.bytes_total}</td>
                      <td className="p-3">{f.latest_anomaly_score}</td>
                      <td className="p-3">
                        <TierBadge value={f.latest_classification_tier} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === "alerts" && (
          <div className="space-y-4">
            <h2 className="text-xl font-bold">Alert Management & SHAP Explainability</h2>
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="space-y-3 lg:col-span-2">
                {alerts.length === 0 && (
                  <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-xs text-slate-400">
                    No alerts yet. Go to <strong className="text-slate-200">Dataset Management</strong> and click{" "}
                    <strong className="text-sky-300">Extract &amp; Detect</strong> on your uploaded PCAPs to extract flows and run ML detection.
                  </div>
                )}
                {alerts.map((a) => (
                  <div
                    key={a.alert_id}
                    className="rounded-xl border border-slate-800 bg-slate-900 p-4"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-semibold text-white">{a.title}</div>
                      <TierBadge value={a.classification_tier} />
                    </div>
                    <p className="mt-1 text-xs text-slate-400">{a.summary}</p>
                    <div className="mt-3 flex gap-2">
                      <button
                        onClick={() =>
                          apiFetch(`/detections/${a.detection_result_id}/explain`).then(setShapDetail)
                        }
                        className="rounded bg-slate-800 px-2.5 py-1 text-xs text-sky-300 hover:bg-slate-700"
                      >
                        Inspect SHAP
                      </button>
                      <button
                        onClick={() => handleEscalateAlert(a)}
                        className="rounded bg-orange-500/20 px-2.5 py-1 text-xs text-orange-300 hover:bg-orange-500/30"
                      >
                        Escalate to Incident
                      </button>
                    </div>
                  </div>
                ))}
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                <h3 className="text-sm font-semibold">SHAP Feature Contributions</h3>
                {shapDetail ? (
                  <div className="mt-3 space-y-2 text-xs">
                    <div>
                      Class: <span className="font-mono text-sky-300">{shapDetail.predicted_class}</span>
                    </div>
                    <div>Anomaly Score: {shapDetail.anomaly_score}</div>
                    <div className="space-y-1.5 pt-2">
                      {(shapDetail.shap_features || []).map((sf: any) => (
                        <div key={sf.feature} className="flex justify-between border-b border-slate-800 pb-1">
                          <span className="font-mono text-slate-300">{sf.feature}</span>
                          <span className={sf.shap_value >= 0 ? "text-orange-300" : "text-emerald-300"}>
                            {sf.shap_value > 0 ? "+" : ""}
                            {sf.shap_value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="mt-2 text-xs text-slate-500">Select an alert to inspect SHAP values.</p>
                )}
              </div>
            </div>
          </div>
        )}

        {tab === "incidents" && (
          <div className="space-y-4">
            <h2 className="text-xl font-bold">Incident Management</h2>
            <div className="space-y-3">
              {incidents.length === 0 && (
                <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-xs text-slate-400">
                  No incidents yet. Escalate an alert from <strong className="text-slate-200">Alert Management</strong> to create an incident and launch the 5-agent investigation.
                </div>
              )}
              {incidents.map((inc) => (
                <div
                  key={inc.incident_id}
                  className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900 p-4"
                >
                  <div>
                    <div className="font-semibold text-white">{inc.title}</div>
                    <div className="mt-1 flex items-center gap-2 text-xs text-slate-400">
                      <span>Severity: {inc.severity}</span>
                      <span>Status: {inc.status}</span>
                      <TierBadge value={inc.verdict} />
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleRunInvestigation(inc.incident_id)}
                      className="rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400"
                    >
                      Run 5-Agent Investigation
                    </button>
                    <button
                      onClick={() => handleGenerateReport(inc.incident_id)}
                      className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800"
                    >
                      Generate Report
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === "investigations" && (
          <div className="space-y-5">
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-bold">Investigation Workspace & Agent History</h2>
              <select
                value={activeInv?.investigation_id || ""}
                onChange={(e) =>
                  e.target.value &&
                  apiFetch(`/investigations/${e.target.value}`).then(setActiveInv)
                }
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs"
              >
                <option value="">Select investigation...</option>
                {investigations.map((i) => (
                  <option key={i.investigation_id} value={i.investigation_id}>
                    {i.investigation_id.slice(0, 8)} — {i.validation_status}
                  </option>
                ))}
              </select>
            </div>
            {activeInv ? (
              <>
                <AgentFlowGraph runs={activeInv.agent_runs || []} />
                <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold">Executive Summary & Validation</h3>
                    <TierBadge value={activeInv.validation_status} />
                  </div>
                  <p className="mt-2 text-xs text-slate-300">{activeInv.executive_summary}</p>
                  <p className="mt-1 text-xs text-slate-400">Hypothesis: {activeInv.hypothesis}</p>
                </div>
                <div className="grid gap-4 lg:grid-cols-2">
                  <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                    <h3 className="mb-3 text-sm font-semibold">Verified Evidence Items</h3>
                    <div className="space-y-2 text-xs">
                      {(activeInv.evidence_items || []).map((ev: any) => (
                        <div key={ev.id} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                          <div className="flex justify-between">
                            <span className="font-mono text-sky-300">{ev.evidence_type}</span>
                            <TierBadge value={ev.validation_verdict} />
                          </div>
                          <p className="mt-1 text-slate-200">{ev.claim_text}</p>
                          <p className="mt-1 text-[11px] text-slate-500">{ev.validator_notes}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                    <h3 className="mb-3 text-sm font-semibold">Recommendations (Human Approval Required)</h3>
                    <div className="space-y-3 text-xs">
                      {(activeInv.recommendations || []).map((rec: any) => (
                        <div key={rec.id} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-white">{rec.title}</span>
                            <TierBadge value={rec.approval_status} />
                          </div>
                          <p className="mt-1 text-slate-300">{rec.description}</p>
                          <p className="mt-1 text-[11px] text-amber-300/80">Impact: {rec.risk_impact}</p>
                          {rec.approval_status === "pending_approval" && (
                            <div className="mt-2 flex gap-2">
                              <button
                                onClick={() => handleDecision(activeInv.investigation_id, rec.id, "approved")}
                                className="rounded bg-emerald-500/20 px-2.5 py-1 text-emerald-300 hover:bg-emerald-500/30"
                              >
                                Approve
                              </button>
                              <button
                                onClick={() => handleDecision(activeInv.investigation_id, rec.id, "rejected")}
                                className="rounded bg-rose-500/20 px-2.5 py-1 text-rose-300 hover:bg-rose-500/30"
                              >
                                Reject
                              </button>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <p className="text-xs text-slate-400">Run or select an investigation to inspect the LangGraph state.</p>
            )}
          </div>
        )}

        {tab === "threat_intel" && (
          <div className="space-y-4">
            <h2 className="text-xl font-bold">Threat Intelligence Viewer (Hybrid RAG + RRF + Reranker)</h2>
            <form onSubmit={handleRagSearch} className="flex gap-2">
              <input
                value={ragQuery}
                onChange={(e) => setRagQuery(e.target.value)}
                className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
                placeholder="Search MITRE ATT&CK, CVEs, or playbooks..."
              />
              <button
                type="submit"
                className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950"
              >
                Hybrid Search
              </button>
            </form>
            <div className="space-y-3">
              {ragResults.map((r) => (
                <div key={r.chunk_id} className="rounded-xl border border-slate-800 bg-slate-900 p-4 text-xs">
                  <div className="flex justify-between">
                    <span className="font-semibold text-sky-300">
                      [{r.external_id}] {r.title}
                    </span>
                    <span className="text-slate-400">
                      RRF: {r.rrf_score} | Rerank: {r.rerank_score}
                    </span>
                  </div>
                  <p className="mt-2 whitespace-pre-wrap text-slate-300">{r.content}</p>
                </div>
              ))}
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 text-xs">
              <h3 className="mb-2 font-semibold text-slate-200">Ingested Knowledge Base ({ragDocs.length})</h3>
              <ul className="space-y-1 text-slate-400">
                {ragDocs.map((d) => (
                  <li key={d.document_id}>
                    <span className="font-mono text-sky-300">{d.external_id}</span> — {d.title} ({d.source_type})
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {tab === "reports" && (
          <div className="space-y-4">
            <h2 className="text-xl font-bold">Incident Reports</h2>
            {reportPreview ? (
              <pre className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900 p-4 text-xs text-slate-200">
                {reportPreview.content_preview}
              </pre>
            ) : (
              <p className="text-xs text-slate-400">Generate a report from the Incident Management tab.</p>
            )}
          </div>
        )}

        {tab === "models" && (
          <div className="space-y-4">
            <h2 className="text-xl font-bold">Model Performance Analytics</h2>
            <div className="space-y-3">
              {models.map((m) => (
                <div key={m.id} className="rounded-xl border border-slate-800 bg-slate-900 p-4 text-xs">
                  <div className="flex justify-between">
                    <span className="font-semibold text-white">
                      {m.name} ({m.version})
                    </span>
                    <TierBadge value={m.stage} />
                  </div>
                  <div className="mt-1 text-slate-400">Dataset: {m.training_dataset_ref}</div>
                  <pre className="mt-2 rounded bg-slate-950 p-2 text-[11px] text-slate-300">
                    {JSON.stringify({ thresholds: m.threshold_config, metrics: m.metrics }, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === "audit" && (
          <div className="space-y-4">
            <h2 className="text-xl font-bold">Immutable Audit Logs</h2>
            <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="p-3">Timestamp</th>
                    <th className="p-3">Actor</th>
                    <th className="p-3">Action</th>
                    <th className="p-3">Resource</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {auditLogs.map((l) => (
                    <tr key={l.id}>
                      <td className="p-3 font-mono text-slate-400">{l.created_at}</td>
                      <td className="p-3">{l.actor_type}</td>
                      <td className="p-3 font-mono text-sky-300">{l.action}</td>
                      <td className="p-3">
                        {l.resource_type} {l.resource_id?.slice(0, 8)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
