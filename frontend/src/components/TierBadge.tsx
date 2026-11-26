import React from "react";

const STYLES: Record<string, string> = {
  benign: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  anomalous: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  suspicious: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  confirmed_malicious: "bg-rose-500/20 text-rose-300 border-rose-500/50",
  verified: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  supported: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  flagged: "bg-rose-500/20 text-rose-300 border-rose-500/50",
  unsupported: "bg-rose-500/20 text-rose-300 border-rose-500/50",
  pending_approval: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  approved: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  rejected: "bg-slate-600/30 text-slate-300 border-slate-500/40",
};

export const TierBadge: React.FC<{ value: string }> = ({ value }) => {
  const cls = STYLES[value] || "bg-slate-700/40 text-slate-200 border-slate-600";
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${cls}`}>
      {value.replace(/_/g, " ")}
    </span>
  );
};
