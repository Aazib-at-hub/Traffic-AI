import React from "react";
import ReactFlow, { Background, Controls, Edge, Node } from "reactflow";

interface AgentRunSummary {
  agent_name: string;
  status: string;
  latency_ms: number;
}

const AGENT_ORDER = [
  "Detection Analyst Agent",
  "Threat Intelligence Agent",
  "Investigation Coordinator Agent",
  "Response Advisor Agent",
  "Evidence Validator Agent",
];

export const AgentFlowGraph: React.FC<{ runs: AgentRunSummary[] }> = ({ runs }) => {
  const latestByAgent = new Map<string, AgentRunSummary>();
  for (const r of runs) latestByAgent.set(r.agent_name, r);

  const nodes: Node[] = AGENT_ORDER.map((name, idx) => {
    const run = latestByAgent.get(name);
    return {
      id: `agent-${idx}`,
      position: { x: idx * 215, y: 40 },
      data: {
        label: (
          <div className="text-left">
            <div className="text-xs font-semibold text-slate-100">{name.replace(" Agent", "")}</div>
            <div className="text-[11px] text-slate-400">
              {run ? `${run.status} (${run.latency_ms}ms)` : "idle"}
            </div>
          </div>
        ),
      },
      style: {
        background: run ? "#0f172a" : "#1e293b",
        border: run ? "1px solid #38bdf8" : "1px solid #475569",
        borderRadius: 10,
        padding: 10,
        width: 185,
      },
    };
  });

  const edges: Edge[] = [
    { id: "e0-1", source: "agent-0", target: "agent-1", animated: true },
    { id: "e1-2", source: "agent-1", target: "agent-2", animated: true },
    { id: "e2-3", source: "agent-2", target: "agent-3", animated: true },
    { id: "e3-4", source: "agent-3", target: "agent-4", animated: true },
    {
      id: "e4-2",
      source: "agent-4",
      target: "agent-2",
      label: "revise (max 2)",
      style: { stroke: "#f59e0b", strokeDasharray: "5 5" },
    },
  ];

  return (
    <div className="h-56 w-full rounded-xl border border-slate-800 bg-slate-950">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
        <Background color="#1e293b" gap={18} />
        <Controls />
      </ReactFlow>
    </div>
  );
};
