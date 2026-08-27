import { useMemo, useState } from "react";
import {
  DfdNode,
  DfdFlow,
  NodeKind,
  analyze,
  parseDescription,
  STRIDE_META,
  StrideCategory,
  SEVERITY_META,
  Severity,
  ThreatStatus,
  TrustLevel,
  threatKey,
  makeId,
} from "./lib/threatEngine";

const TRUST_TOKEN: Record<TrustLevel, string> = {
  Untrusted: "var(--color-stride-d)",
  "Semi-Trusted": "var(--color-stride-t)",
  Trusted: "var(--color-stride-s)",
};

const SEVERITY_ORDER: Severity[] = ["Critical", "High", "Medium", "Low"];
import { PRESETS } from "./lib/presets";
import DFDDiagram from "./components/DFDDiagram";

const TIPS = [
  { t: "Map Data Flows", d: "Diagram how data moves to expose vulnerable hops." },
  { t: "Define Trust Boundaries", d: "Mark every trust-level change (e.g. client → server)." },
  { t: "Apply STRIDE", d: "Analyze each component and flow systematically." },
  { t: "Use Numbered Threat IDs", d: "Map threats to DFD elements with IDs (T1, T2…)." },
  { t: "Involve the Team", d: "Include developers, designers and stakeholders." },
  { t: "Iterate", d: "Update the model as the system evolves." },
  { t: "Document", d: "Record threats, mitigations and DFD mappings." },
];

const KIND_LABEL: Record<NodeKind, string> = {
  external: "External entity",
  process: "Process",
  datastore: "Data store",
};

const gid = (p: string) => makeId(p);

const dlBtn = (onClick: () => void, label: string) => (
  <button
    key={label}
    onClick={onClick}
    title={`Download ${label}`}
    className="flex items-center gap-1 rounded-md border border-line bg-panel hover:border-stride-s/60 hover:text-stride-s text-fg-dim font-mono text-[11px] font-semibold px-2.5 py-1.5 transition-colors"
  >
    <span className="text-sm leading-none">↓</span>
    {label}
  </button>
);

const exBtn = (onClick: () => void, title: string, sub: string) => (
  <button
    key={title}
    onClick={onClick}
    className="flex items-center gap-2 rounded-md border border-stride-s/40 bg-stride-s/10 hover:bg-stride-s/20 text-stride-s px-3.5 py-2 transition-colors"
  >
    <span className="text-base leading-none">↓</span>
    <span className="text-left leading-tight">
      <span className="block text-xs font-semibold">{title}</span>
      <span className="block font-mono text-[10px] uppercase tracking-wider opacity-80">{sub}</span>
    </span>
  </button>
);

export default function App() {
  const [nodes, setNodes] = useState<DfdNode[]>(PRESETS[0].nodes);
  const [flows, setFlows] = useState<DfdFlow[]>(PRESETS[0].flows);
  const [desc, setDesc] = useState("");
  const [uploadName, setUploadName] = useState<string | null>(null);
  const [uploadUrl, setUploadUrl] = useState<string | null>(null);
  const [parseInfo, setParseInfo] = useState<
    { components: number; flows: number; unrecognized: string[] } | null
  >(null);

  // Review status is tracked here (keyed by stable threatKey) and merged onto the
  // regenerated model, since analyze() reassigns T-IDs by risk on every change.
  const [statusOverrides, setStatusOverrides] = useState<Record<string, ThreatStatus>>({});

  const model = useMemo(() => analyze(nodes, flows), [nodes, flows]);
  const threats = useMemo(
    () => model.threats.map((t) => ({ ...t, status: statusOverrides[threatKey(t)] ?? t.status })),
    [model, statusOverrides],
  );
  const setStatus = (t: { scope: string; targetId: string; category: string; rationale: string }, status: ThreatStatus) =>
    setStatusOverrides((s) => ({ ...s, [threatKey(t as any)]: status }));

  const loadPreset = (key: string) => {
    const p = PRESETS.find((x) => x.key === key)!;
    setNodes(p.nodes.map((n) => ({ ...n })));
    setFlows(p.flows.map((f) => ({ ...f })));
  };

  const parse = () => {
    const parsed = parseDescription(desc);
    if (!parsed) {
      setParseInfo(desc.trim() ? { components: 0, flows: 0, unrecognized: [] } : null);
      return;
    }
    setNodes(parsed.nodes);
    setFlows(parsed.flows);
    setParseInfo({
      components: parsed.nodes.length,
      flows: parsed.flows.length,
      unrecognized: parsed.unrecognized,
    });
  };

  const addNode = () =>
    setNodes((ns) => [...ns, { id: gid("n"), name: "New Component", kind: "process", zone: "Backend Boundary" }]);
  const updNode = (id: string, patch: Partial<DfdNode>) =>
    setNodes((ns) => ns.map((n) => (n.id === id ? { ...n, ...patch } : n)));
  const delNode = (id: string) => {
    setNodes((ns) => ns.filter((n) => n.id !== id));
    setFlows((fs) => fs.filter((f) => f.from !== id && f.to !== id));
  };

  const addFlow = () =>
    setFlows((fs) =>
      nodes.length >= 2
        ? [...fs, { id: gid("f"), from: nodes[0].id, to: nodes[1].id, label: "Data" }]
        : fs,
    );
  const updFlow = (id: string, patch: Partial<DfdFlow>) =>
    setFlows((fs) => fs.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  const delFlow = (id: string) => setFlows((fs) => fs.filter((f) => f.id !== id));

  const onUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadName(file.name);
    setUploadUrl(URL.createObjectURL(file));
  };

  const triggerDownload = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Export the live DFD as a standalone .svg (inlining CSS variables so it
  // renders outside the app).
  const exportSVG = () => {
    const svg = document.getElementById("dfd-svg") as SVGSVGElement | null;
    if (!svg) return;
    const clone = svg.cloneNode(true) as SVGSVGElement;
    const cs = getComputedStyle(document.documentElement);
    let vars = "";
    for (let i = 0; i < cs.length; i++) {
      const name = cs[i];
      if (name.startsWith("--color-") || name.startsWith("--font-"))
        vars += `${name}:${cs.getPropertyValue(name)};`;
    }
    clone.setAttribute("style", `${vars}background:#ffffff;`);
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    const data = `<?xml version="1.0" encoding="UTF-8"?>\n${new XMLSerializer().serializeToString(clone)}`;
    triggerDownload(new Blob([data], { type: "image/svg+xml" }), "threat-model-dfd.svg");
  };

  // Export a Markdown threat report of the current model.
  const exportReport = () => {
    const nameOf = (id: string) => nodes.find((n) => n.id === id)?.name ?? id;
    const lines: string[] = [];
    lines.push("# STRIDE Threat Model Report", "");
    lines.push(`_Generated ${new Date().toISOString().slice(0, 10)} · ${nodes.length} elements · ${flows.length} flows · ${threats.length} threats_`, "");
    lines.push("## Trust boundaries", "");
    for (const b of model.boundaries)
      lines.push(`- **${b.id} · ${b.zone}** _(${b.trustLevel})_ — ${b.nodeIds.map(nameOf).join(", ")}. ${b.rationale}`);
    lines.push("", "## Data flows", "");
    for (const f of flows)
      lines.push(`- ${nameOf(f.from)} → ${nameOf(f.to)}: ${f.label}${f.protocol ? ` [${f.protocol}]` : ""}${model.crossings.has(f.id) ? " _(crosses boundary)_" : ""}`);
    lines.push("", "## Identified threats", "", "_Ordered by risk — highest first (risk = likelihood × impact)._", "");
    for (const t of threats) {
      lines.push(`### ${t.id}: [${t.severity} · risk ${t.risk}/9] ${t.category} — ${t.targetLabel}`, "");
      lines.push(`- **Status**: ${t.status}`);
      lines.push(`- **Trace**: ${t.trace}`);
      lines.push(`- **Risk**: ${t.severity} — likelihood ${t.likelihood}/3 × impact ${t.impact}/3 = ${t.risk}/9`);
      lines.push(`- **Description**: ${t.rationale}`);
      lines.push(`- **Mitigation**: ${t.mitigation}`);
      lines.push(`- **Security Controls**: ${t.securityControls}`);
      lines.push(`- **OWASP ASVS**: ${t.owaspAsvs}`);
      lines.push(`- **OWASP SAMM**: ${t.owaspSamm}`, "");
    }
    triggerDownload(new Blob([lines.join("\n")], { type: "text/markdown" }), "threat-model-report.md");
  };

  const exportJSON = () => {
    const payload = { nodes, flows, boundaries: model.boundaries, threats };
    triggerDownload(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }), "threat-model.json");
  };

  // group threats by flow for the results list
  const flowGroups = flows.map((f) => ({
    flow: f,
    label: `${nodes.find((n) => n.id === f.from)?.name} → ${nodes.find((n) => n.id === f.to)?.name}`,
    threats: threats.filter((t) => t.scope === "flow" && t.targetId === f.id),
  }));
  const elementGroups = [
    ...nodes.map((n) => ({
      key: n.id,
      label: n.name,
      threats: threats.filter((t) => t.scope === "node" && t.targetId === n.id),
    })),
    ...model.boundaries.map((b) => ({
      key: b.zone,
      label: b.zone,
      threats: threats.filter((t) => t.scope === "boundary" && t.targetId === b.zone),
    })),
  ].filter((g) => g.threats.length > 0);

  const counts = (Object.keys(STRIDE_META) as StrideCategory[]).map((c) => ({
    c,
    n: threats.filter((t) => t.category === c).length,
  }));

  const severityCounts = SEVERITY_ORDER.map((s) => ({
    s,
    n: threats.filter((t) => t.severity === s).length,
  }));

  return (
    <div className="min-h-full w-full text-fg">
      {/* header */}
      <header className="border-b border-line bg-panel/60 backdrop-blur sticky top-0 z-10">
        <div className="mx-auto max-w-[1400px] px-6 py-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="size-9 rounded-md border border-line-bright bg-panel-2 grid place-items-center font-mono text-stride-s font-bold">
              ⛬
            </div>
            <div>
              <h1 className="font-slab text-lg leading-none font-extrabold tracking-tight">
                STRIDE<span className="text-stride-s">/</span>MODELER
              </h1>
              <p className="text-[11px] font-mono text-fg-dim mt-1 uppercase tracking-widest">
                data-flow threat analysis console
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-4 font-mono text-[11px] text-fg-dim">
              <span>{nodes.length} elements</span>
              <span className="text-line-bright">·</span>
              <span>{flows.length} flows</span>
              <span className="text-line-bright">·</span>
              <span className="text-stride-d">{model.threats.length} threats</span>
            </div>
            <div className="flex items-center gap-1.5">
              {dlBtn(exportSVG, "SVG")}
              {dlBtn(exportReport, ".md")}
              {dlBtn(exportJSON, "JSON")}
            </div>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1400px] px-6 py-8 grid grid-cols-1 lg:grid-cols-[400px_1fr] gap-8 items-start">
        {/* ---------------- LEFT: input ---------------- */}
        <div className="flex flex-col gap-6 lg:sticky lg:top-24">
          <Section step="01" title="Provide system details">
            <textarea
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              placeholder="Describe your architecture in plain English, e.g.&#10;&quot;Browser sends credentials to the backend API, which writes to the database and calls the Stripe payment gateway.&quot;"
              className="w-full h-28 resize-none rounded-md bg-ink border border-line focus:border-stride-s/60 outline-none px-3 py-2.5 text-sm placeholder:text-fg-faint transition-colors"
            />
            <div className="flex gap-2 mt-2">
              <button
                onClick={parse}
                className="flex-1 rounded-md bg-stride-s/15 border border-stride-s/40 text-stride-s font-mono text-xs font-semibold py-2 hover:bg-stride-s/25 transition-colors uppercase tracking-wider"
              >
                Parse → Model
              </button>
              <label className="rounded-md border border-line text-fg-dim font-mono text-xs py-2 px-3 hover:border-line-bright hover:text-fg cursor-pointer transition-colors flex items-center gap-1.5">
                <input type="file" accept="image/*" className="hidden" onChange={onUpload} />
                ↑ Upload DFD
              </label>
            </div>
            {uploadName && (
              <div className="mt-2 text-[11px] font-mono text-fg-dim truncate">
                ref: {uploadName}
              </div>
            )}
            {parseInfo && (
              <div className="mt-3 rounded-md border border-line bg-ink px-3 py-2.5 text-[11px] leading-relaxed">
                {parseInfo.components >= 2 ? (
                  <div className="font-mono text-fg-dim">
                    <span className="text-stride-s font-semibold">✓ Parsed</span>{" "}
                    {parseInfo.components} components · {parseInfo.flows} data flows.
                    Review & correct them in step 03 below.
                  </div>
                ) : (
                  <div className="font-mono text-stride-d">
                    ⚠ Couldn&apos;t identify two or more components. Add connectors like
                    &quot;sends to&quot; / &quot;reads from&quot;, or refine manually below.
                  </div>
                )}
                {parseInfo.unrecognized.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-line/60 text-fg-dim">
                    <span className="text-stride-t font-semibold">Couldn&apos;t classify:</span>{" "}
                    {parseInfo.unrecognized.map((u, i) => (
                      <span key={u} className="font-mono text-fg">
                        {i > 0 && ", "}
                        {u}
                      </span>
                    ))}
                    <span className="text-fg-faint">
                      {" "}
                      — add them as components in step 03 if they matter.
                    </span>
                  </div>
                )}
              </div>
            )}
          </Section>

          <Section step="02" title="Or start from a reference architecture">
            <div className="flex flex-col gap-2">
              {PRESETS.map((p) => (
                <button
                  key={p.key}
                  onClick={() => loadPreset(p.key)}
                  className="text-left rounded-md border border-line bg-panel hover:border-stride-s/50 hover:bg-panel-2 transition-colors px-3 py-2.5 group"
                >
                  <div className="font-semibold text-sm group-hover:text-stride-s transition-colors">{p.name}</div>
                  <div className="text-[11px] text-fg-dim mt-0.5">{p.desc}</div>
                </button>
              ))}
            </div>
          </Section>

          <Section step="03" title="Refine components & flows">
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono text-[11px] uppercase tracking-wider text-fg-dim">Components</span>
              <button onClick={addNode} className="font-mono text-[11px] text-stride-s hover:underline">+ add</button>
            </div>
            <div className="flex flex-col gap-1.5 mb-4">
              {nodes.map((n) => (
                <div key={n.id} className="flex gap-1.5 items-center">
                  <input
                    value={n.name}
                    onChange={(e) => updNode(n.id, { name: e.target.value })}
                    className="flex-1 min-w-0 rounded bg-ink border border-line px-2 py-1.5 text-xs outline-none focus:border-line-bright"
                  />
                  <select
                    value={n.kind}
                    onChange={(e) => updNode(n.id, { kind: e.target.value as NodeKind })}
                    className="rounded bg-ink border border-line px-1.5 py-1.5 text-[11px] font-mono outline-none focus:border-line-bright"
                  >
                    {(Object.keys(KIND_LABEL) as NodeKind[]).map((k) => (
                      <option key={k} value={k}>{KIND_LABEL[k]}</option>
                    ))}
                  </select>
                  <input
                    value={n.zone}
                    onChange={(e) => updNode(n.id, { zone: e.target.value })}
                    title="Trust zone"
                    className="w-24 rounded bg-ink border border-line px-2 py-1.5 text-[11px] outline-none focus:border-line-bright text-boundary"
                  />
                  <button onClick={() => delNode(n.id)} className="text-fg-faint hover:text-stride-d px-1 text-sm">×</button>
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between mb-2">
              <span className="font-mono text-[11px] uppercase tracking-wider text-fg-dim">Data flows</span>
              <button onClick={addFlow} className="font-mono text-[11px] text-stride-s hover:underline">+ add</button>
            </div>
            <div className="flex flex-col gap-1.5">
              {flows.map((f) => (
                <div key={f.id} className="flex gap-1.5 items-center">
                  <select
                    value={f.from}
                    onChange={(e) => updFlow(f.id, { from: e.target.value })}
                    className="w-20 rounded bg-ink border border-line px-1.5 py-1.5 text-[11px] outline-none focus:border-line-bright"
                  >
                    {nodes.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
                  </select>
                  <span className="text-flow text-xs">→</span>
                  <select
                    value={f.to}
                    onChange={(e) => updFlow(f.id, { to: e.target.value })}
                    className="w-20 rounded bg-ink border border-line px-1.5 py-1.5 text-[11px] outline-none focus:border-line-bright"
                  >
                    {nodes.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
                  </select>
                  <input
                    value={f.label}
                    onChange={(e) => updFlow(f.id, { label: e.target.value })}
                    className="flex-1 min-w-0 rounded bg-ink border border-line px-2 py-1.5 text-[11px] outline-none focus:border-line-bright"
                  />
                  <input
                    value={f.protocol ?? ""}
                    onChange={(e) => updFlow(f.id, { protocol: e.target.value })}
                    placeholder="proto"
                    title="Protocol (e.g. HTTPS, mTLS, SQL/TLS)"
                    className="w-16 rounded bg-ink border border-line px-1.5 py-1.5 text-[11px] font-mono outline-none focus:border-line-bright text-flow"
                  />
                  <button onClick={() => delFlow(f.id)} className="text-fg-faint hover:text-stride-d px-1 text-sm">×</button>
                </div>
              ))}
            </div>
          </Section>
        </div>

        {/* ---------------- RIGHT: output ---------------- */}
        <div className="flex flex-col gap-8 min-w-0">
          {/* tips */}
          <div className="rounded-md border border-line bg-panel p-5">
            <h2 className="font-slab text-sm font-bold uppercase tracking-wider text-fg-dim mb-4">
              Tips for effective threat modeling
            </h2>
            <div className="grid sm:grid-cols-2 gap-x-6 gap-y-3">
              {TIPS.map((tip, i) => (
                <div key={tip.t} className="flex gap-3">
                  <span className="font-mono text-[11px] text-stride-s pt-0.5">{String(i + 1).padStart(2, "0")}</span>
                  <div>
                    <div className="text-sm font-semibold">{tip.t}</div>
                    <div className="text-xs text-fg-dim leading-relaxed">{tip.d}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {uploadUrl && (
            <div className="rounded-md border border-line bg-panel p-4">
              <div className="font-mono text-[11px] uppercase tracking-wider text-fg-dim mb-2">Uploaded reference diagram</div>
              <img src={uploadUrl} alt="Uploaded data flow diagram reference" className="max-h-72 rounded border border-line bg-[#0a1119]" />
            </div>
          )}

          {/* export */}
          <div className="rounded-md border border-line bg-panel p-4 flex flex-wrap items-center gap-3">
            <div className="mr-auto">
              <div className="font-slab text-sm font-bold">Download threat model</div>
              <div className="text-xs text-fg-dim">Export the diagram and report — works fully offline.</div>
            </div>
            {exBtn(exportSVG, "Diagram", "SVG")}
            {exBtn(exportReport, "Report", ".md")}
            {exBtn(exportJSON, "Model", ".json")}
          </div>

          {/* diagram */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="font-slab text-lg font-bold">
                Refined Data Flow Diagram
              </h2>
              <span className="font-mono text-[11px] text-fg-dim">trust boundaries · numbered threat IDs</span>
            </div>
            <DFDDiagram nodes={nodes} flows={flows} model={model} />
            <Legend />
          </div>

          {/* trust boundary register */}
          <div>
            <h2 className="font-slab text-lg font-bold mb-3">Trust boundaries</h2>
            <div className="grid sm:grid-cols-2 gap-3">
              {model.boundaries.map((b) => (
                <div key={b.id} className="rounded-md border border-line bg-panel p-3">
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-mono text-[11px] text-boundary shrink-0">{b.id}</span>
                      <span className="font-semibold text-sm truncate">{b.zone}</span>
                    </div>
                    <span
                      className="shrink-0 font-mono text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded"
                      style={{
                        color: TRUST_TOKEN[b.trustLevel],
                        border: `1px solid ${TRUST_TOKEN[b.trustLevel]}66`,
                        background: `${TRUST_TOKEN[b.trustLevel]}14`,
                      }}
                    >
                      {b.trustLevel}
                    </span>
                  </div>
                  <div className="text-[11px] text-fg-dim leading-relaxed">{b.rationale}</div>
                  <div className="text-[11px] text-fg-faint mt-1.5 font-mono truncate">
                    {b.nodeIds.map((id) => nodes.find((n) => n.id === id)?.name).filter(Boolean).join(" · ")}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* threat summary */}
          <div>
            <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
              <h2 className="font-slab text-lg font-bold">Threat surface</h2>
              <div className="flex items-center gap-1.5">
                {severityCounts.map(({ s, n }) => (
                  <span
                    key={s}
                    className="flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[11px]"
                    style={{ borderColor: `${SEVERITY_META[s].token}66`, color: SEVERITY_META[s].token }}
                    title={`${n} ${s.toLowerCase()}-risk threats`}
                  >
                    <span className="size-1.5 rounded-full" style={{ background: SEVERITY_META[s].token }} />
                    {s} <span className="font-bold">{n}</span>
                  </span>
                ))}
              </div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
              {counts.map(({ c, n }) => (
                <div
                  key={c}
                  className="rounded-md border border-line bg-panel px-3 py-2.5"
                  style={{ borderTopColor: STRIDE_META[c].token, borderTopWidth: 2 }}
                >
                  <div className="flex items-baseline justify-between">
                    <span className="font-mono text-base font-bold" style={{ color: STRIDE_META[c].token }}>{n}</span>
                    <span className="font-mono text-[11px]" style={{ color: STRIDE_META[c].token }}>{STRIDE_META[c].tag}</span>
                  </div>
                  <div className="text-[11px] text-fg-dim mt-0.5 leading-tight">{c}</div>
                </div>
              ))}
            </div>
          </div>

          {/* identified threats */}
          <div>
            <h2 className="font-slab text-lg font-bold mb-3">Identified threats</h2>
            <div className="flex flex-col gap-5">
              {flowGroups.filter((g) => g.threats.length).map((g) => (
                <ThreatGroup key={`flow-${g.flow.id}`} title={`Threats for ${g.label}`} crossing={model.crossings.has(g.flow.id)} threats={g.threats} onStatus={setStatus} />
              ))}
              {elementGroups.map((g) => (
                <ThreatGroup key={`el-${g.key}`} title={`Threats for ${g.label}`} threats={g.threats} onStatus={setStatus} />
              ))}
            </div>
          </div>

          <footer className="text-[11px] font-mono text-fg-faint border-t border-line pt-4 pb-8">
            Refined Data Flow Diagram with Trust Boundaries and Numbered Threat IDs · STRIDE methodology ·
            model updates live as the architecture changes.
          </footer>
        </div>
      </main>
    </div>
  );
}

function Section({ step, title, children }: { step: string; title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-md border border-line bg-panel p-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="font-mono text-[11px] text-stride-s border border-stride-s/40 rounded px-1.5 py-0.5">STEP {step}</span>
        <h2 className="font-semibold text-sm">{title}</h2>
      </div>
      {children}
    </section>
  );
}

type ThreatRow = {
  id: string;
  category: StrideCategory;
  scope: string;
  targetId: string;
  severity: Severity;
  status: ThreatStatus;
  trace: string;
  likelihood: number;
  impact: number;
  risk: number;
  rationale: string;
  mitigation: string;
  securityControls: string;
  owaspAsvs: string;
  owaspSamm: string;
};

const STATUSES: ThreatStatus[] = ["Open", "Mitigated", "Accepted"];
const STATUS_TOKEN: Record<ThreatStatus, string> = {
  Open: "var(--color-stride-d)",
  Mitigated: "var(--color-stride-s)",
  Accepted: "var(--color-fg-dim)",
};

function ThreatGroup({
  title,
  threats,
  crossing,
  onStatus,
}: {
  title: string;
  threats: ThreatRow[];
  crossing?: boolean;
  onStatus: (t: ThreatRow, s: ThreatStatus) => void;
}) {
  return (
    <div className="rounded-md border border-line bg-panel overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-line bg-panel-2">
        <h3 className="font-semibold text-sm">{title}</h3>
        {crossing !== undefined && (
          <span className={`font-mono text-[10px] uppercase tracking-wider px-2 py-0.5 rounded ${crossing ? "text-flow border border-flow/40" : "text-fg-dim border border-line"}`}>
            {crossing ? "crosses boundary" : "internal"}
          </span>
        )}
      </div>
      <ul className="divide-y divide-line/60">
        {threats.map((t) => (
          <ThreatItem key={t.id} t={t} onStatus={onStatus} />
        ))}
      </ul>
    </div>
  );
}

function ThreatItem({ t, onStatus }: { t: ThreatRow; onStatus: (t: ThreatRow, s: ThreatStatus) => void }) {
  const [open, setOpen] = useState(false);
  const m = STRIDE_META[t.category];
  return (
    <li className={open ? "bg-panel-2/40" : "hover:bg-panel-2/50 transition-colors"}>
      <div className="w-full flex items-center gap-3 px-4 py-3">
        <button
          onClick={() => setOpen((o) => !o)}
          className="flex items-center gap-3 text-left min-w-0 flex-1"
          aria-expanded={open}
        >
          <span className={`font-mono text-fg-faint text-xs shrink-0 transition-transform ${open ? "rotate-90" : ""}`}>▶</span>
          <span className="font-mono text-sm font-bold shrink-0 w-9" style={{ color: m.token }}>{t.id}</span>
          <span
            className="shrink-0 size-6 rounded grid place-items-center font-mono text-[11px] font-bold"
            style={{ color: m.token, border: `1px solid ${m.token}`, background: `${m.token}18` }}
          >
            {m.tag}
          </span>
          <span className="text-sm font-semibold min-w-0 flex-1 truncate">
            {t.category} <span className="font-mono text-[11px] text-fg-dim">(STRIDE: {t.category})</span>
          </span>
        </button>
        <span className="shrink-0 font-mono text-[10px] text-fg-faint hidden sm:inline" title="Risk = likelihood × impact">
          L{t.likelihood}×I{t.impact}
        </span>
        <span
          className="shrink-0 font-mono text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded flex items-center gap-1"
          style={{
            color: SEVERITY_META[t.severity].token,
            border: `1px solid ${SEVERITY_META[t.severity].token}66`,
            background: `${SEVERITY_META[t.severity].token}14`,
          }}
          title={`Risk score ${t.risk}/9`}
        >
          {t.severity}
          <span className="opacity-70">{t.risk}</span>
        </span>
        <select
          value={t.status}
          onChange={(e) => onStatus(t, e.target.value as ThreatStatus)}
          title="Review status"
          className="shrink-0 font-mono text-[10px] font-bold uppercase tracking-wider rounded px-1.5 py-0.5 bg-transparent outline-none cursor-pointer"
          style={{
            color: STATUS_TOKEN[t.status],
            border: `1px solid ${STATUS_TOKEN[t.status]}66`,
          }}
        >
          {STATUSES.map((s) => (
            <option key={s} value={s} className="bg-panel text-fg">{s}</option>
          ))}
        </select>
      </div>
      {open && (
        <div className="px-4 pb-4 pl-[4.5rem]">
          <div className="mb-2.5 font-mono text-[11px] text-fg-dim bg-ink border border-line rounded px-2.5 py-1.5 overflow-x-auto">
            <span className="text-boundary font-semibold">trace:</span> {t.trace}
          </div>
          <ul className="flex flex-col gap-2.5 text-xs leading-relaxed">
            <DetailRow
              label="Risk"
              value={`${t.severity} — likelihood ${t.likelihood}/3 × impact ${t.impact}/3 = ${t.risk}/9`}
              token={SEVERITY_META[t.severity].token}
            />
            <DetailRow label="Description" value={t.rationale} token={m.token} />
            <DetailRow label="Mitigation" value={t.mitigation} token={m.token} />
            <DetailRow label="Security Controls" value={t.securityControls} token={m.token} />
            <DetailRow label="OWASP ASVS" value={t.owaspAsvs} token={m.token} mono />
            <DetailRow label="OWASP SAMM" value={t.owaspSamm} token={m.token} mono />
          </ul>
        </div>
      )}
    </li>
  );
}

function DetailRow({ label, value, token, mono }: { label: string; value: string; token: string; mono?: boolean }) {
  return (
    <li className="flex gap-2">
      <span className="mt-1.5 size-1.5 rounded-full shrink-0" style={{ background: token }} />
      <span className="text-fg-dim">
        <span className="font-semibold text-fg">{label}:</span>{" "}
        <span className={mono ? "font-mono text-[11px]" : ""}>{value}</span>
      </span>
    </li>
  );
}

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 mt-3 text-[11px] font-mono text-fg-dim">
      <span className="flex items-center gap-1.5"><span className="inline-block w-4 border-t-2 border-dashed" style={{ borderColor: "var(--color-boundary)" }} /> trust boundary</span>
      <span className="flex items-center gap-1.5"><span className="inline-block w-4 border-t-2" style={{ borderColor: "var(--color-flow)" }} /> data flow</span>
      <span className="flex items-center gap-1.5"><span className="inline-block size-3 rounded-full border" style={{ borderColor: "#dc2626", background: "#f5c2c7" }} /> external</span>
      <span className="flex items-center gap-1.5"><span className="inline-block size-3 rounded-sm border" style={{ borderColor: "#2563eb", background: "#c3dbf3" }} /> process</span>
      <span className="flex items-center gap-1.5"><span className="inline-block size-3 border" style={{ borderColor: "#2f6fb0", background: "#cfe0f2" }} /> data store</span>
    </div>
  );
}
