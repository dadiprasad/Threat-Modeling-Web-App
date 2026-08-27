import { useMemo } from "react";
import {
  DfdNode,
  DfdFlow,
  ThreatModel,
  Threat,
  STRIDE_META,
} from "../lib/threatEngine";

interface Props {
  nodes: DfdNode[];
  flows: DfdFlow[];
  model: ThreatModel;
}

const NODE_W = 208;
const NODE_H = 78;
const COL_GAP = 300;
const ROW_GAP = 210;
const PAD_X = 150;
const PAD_Y = 96;
const BPAD = 34; // boundary padding around nodes

interface Placed extends DfdNode {
  x: number;
  y: number;
}

// Longest-path layering so flows point mostly downward.
function layout(nodes: DfdNode[], flows: DfdFlow[]): Map<string, Placed> {
  const layer = new Map<string, number>();
  nodes.forEach((n) => layer.set(n.id, 0));
  const out = new Map<string, string[]>();
  nodes.forEach((n) => out.set(n.id, []));
  flows.forEach((f) => out.get(f.from)?.push(f.to));

  // relax layers (bounded to avoid cycles)
  for (let i = 0; i < nodes.length; i++) {
    for (const f of flows) {
      const nl = (layer.get(f.from) ?? 0) + 1;
      if (nl > (layer.get(f.to) ?? 0)) layer.set(f.to, nl);
    }
  }

  const byLayer = new Map<number, string[]>();
  nodes.forEach((n) => {
    const l = layer.get(n.id) ?? 0;
    if (!byLayer.has(l)) byLayer.set(l, []);
    byLayer.get(l)!.push(n.id);
  });

  const placed = new Map<string, Placed>();
  const layers = [...byLayer.keys()].sort((a, b) => a - b);
  const maxRow = Math.max(...[...byLayer.values()].map((v) => v.length));
  layers.forEach((l) => {
    const ids = byLayer.get(l)!;
    const rowW = (maxRow - 1) * COL_GAP;
    const start = PAD_X + (rowW - (ids.length - 1) * COL_GAP) / 2;
    ids.forEach((id, i) => {
      const n = nodes.find((x) => x.id === id)!;
      placed.set(id, {
        ...n,
        x: start + i * COL_GAP,
        y: PAD_Y + l * ROW_GAP,
      });
    });
  });
  return placed;
}

function threatsFor(model: ThreatModel, scope: Threat["scope"], id: string) {
  return model.threats.filter((t) => t.scope === scope && t.targetId === id);
}

export default function DFDDiagram({ nodes, flows, model }: Props) {
  const placed = useMemo(() => layout(nodes, flows), [nodes, flows]);

  const arr = [...placed.values()];

  // boundary boxes
  const boxes = model.boundaries.map((b) => {
    const ns = b.nodeIds.map((id) => placed.get(id)!).filter(Boolean);
    const minX = Math.min(...ns.map((n) => n.x - NODE_W / 2));
    const maxX = Math.max(...ns.map((n) => n.x + NODE_W / 2));
    const minY = Math.min(...ns.map((n) => n.y - NODE_H / 2));
    const maxY = Math.max(...ns.map((n) => n.y + NODE_H / 2));
    const bt = threatsFor(model, "boundary", b.zone);
    return {
      zone: b.zone,
      x: minX - BPAD,
      y: minY - BPAD - 30,
      w: maxX - minX + BPAD * 2,
      h: maxY - minY + BPAD * 2 + 30,
      threats: bt,
    };
  });

  // Compute the true drawing extents including boundary boxes (whose labels sit
  // above the top row) so nothing gets clipped at the edges, then pad.
  const M = 24; // outer margin
  const minX = Math.min(...arr.map((p) => p.x - NODE_W / 2), ...boxes.map((b) => b.x)) - M;
  const minY = Math.min(...arr.map((p) => p.y - NODE_H / 2), ...boxes.map((b) => b.y)) - M;
  const maxX = Math.max(...arr.map((p) => p.x + NODE_W / 2), ...boxes.map((b) => b.x + b.w)) + M;
  const maxY = Math.max(...arr.map((p) => p.y + NODE_H / 2), ...boxes.map((b) => b.y + b.h)) + M;
  const width = maxX - minX;
  const height = maxY - minY;

  return (
    <div className="overflow-auto rounded-md border border-line bg-white grid-bg">
      <svg
        id="dfd-svg"
        viewBox={`${minX} ${minY} ${width} ${height}`}
        width={width}
        height={height}
        className="block min-w-full"
        style={{ maxWidth: "none" }}
      >
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--color-flow)" />
          </marker>
        </defs>

        {/* trust boundaries */}
        {boxes.map((b) => (
          <g key={b.zone}>
            <rect
              x={b.x}
              y={b.y}
              width={b.w}
              height={b.h}
              rx={10}
              fill="rgba(168,85,247,0.05)"
              stroke="var(--color-boundary)"
              strokeWidth={2}
              strokeDasharray="9 7"
            />
            <text x={b.x + 14} y={b.y + 22} fontSize={14} fontWeight={700} fill="var(--color-boundary)" fontFamily="var(--font-slab)">
              {b.zone}
            </text>
            {b.threats.length > 0 && (
              <text x={b.x + 14} y={b.y + 40} fontSize={11.5} fill="var(--color-boundary)" fontFamily="var(--font-mono)" opacity={0.9}>
                {b.threats.map((t) => `${t.id}:${STRIDE_META[t.category].tag}`).join("  ")}
              </text>
            )}
          </g>
        ))}

        {/* flows */}
        {flows.map((f) => {
          const a = placed.get(f.from)!;
          const b = placed.get(f.to)!;
          if (!a || !b) return null;
          const [x1, y1, x2, y2] = edgePoints(a, b);
          const midX = (x1 + x2) / 2;
          const midY = (y1 + y2) / 2;
          const ft = threatsFor(model, "flow", f.id);
          const cross = model.crossings.has(f.id);
          return (
            <g key={f.id}>
              <line
                x1={x1}
                y1={y1}
                x2={x2}
                y2={y2}
                stroke="var(--color-flow)"
                strokeWidth={2.4}
                markerEnd="url(#arrow)"
                strokeDasharray={cross ? "none" : "6 5"}
                opacity={cross ? 1 : 0.75}
              />
              <FlowLabel x={midX} y={midY} label={f.label} protocol={f.protocol} threats={ft} />
            </g>
          );
        })}

        {/* nodes */}
        {arr.map((n) => {
          const nt = threatsFor(model, "node", n.id);
          return <NodeShape key={n.id} node={n} threats={nt} />;
        })}
      </svg>
    </div>
  );
}

function edgePoints(a: Placed, b: Placed): [number, number, number, number] {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const ang = Math.atan2(dy, dx);
  const hx = NODE_W / 2 + 4;
  const hy = NODE_H / 2 + 4;
  const t1 = clampToBox(ang, hx, hy);
  const t2 = clampToBox(ang + Math.PI, hx, hy);
  return [a.x + t1.x, a.y + t1.y, b.x + t2.x, b.y + t2.y];
}
function clampToBox(ang: number, hx: number, hy: number) {
  const c = Math.cos(ang);
  const s = Math.sin(ang);
  const sx = c === 0 ? Infinity : hx / Math.abs(c);
  const sy = s === 0 ? Infinity : hy / Math.abs(s);
  const scale = Math.min(sx, sy);
  return { x: c * scale, y: s * scale };
}

function FlowLabel({ x, y, label, protocol, threats }: { x: number; y: number; label: string; protocol?: string; threats: Threat[] }) {
  const lines = threats.map((t) => `${t.id}: ${t.category}`);
  const protoLine = protocol ? `⇄ ${protocol}` : "";
  const w = Math.max(label.length, protoLine.length, ...lines.map((l) => l.length), 8) * 6.7 + 20;
  const headH = protoLine ? 33 : 20;
  const h = headH + lines.length * 15 + 6;
  return (
    <g transform={`translate(${x - w / 2}, ${y - h / 2})`}>
      <rect width={w} height={h} rx={5} fill="#ffffff" stroke="var(--color-line-bright)" strokeWidth={1} />
      <text x={10} y={16} fontSize={12} fontWeight={600} fill="var(--color-fg)" fontFamily="var(--font-sans)">
        {label}
      </text>
      {protoLine && (
        <text x={10} y={29} fontSize={10} fill="var(--color-flow)" fontFamily="var(--font-mono)">
          {protoLine}
        </text>
      )}
      {lines.map((l, i) => (
        <text
          key={i}
          x={10}
          y={headH + 13 + i * 15}
          fontSize={11}
          fill={STRIDE_META[threats[i].category].token}
          fontFamily="var(--font-mono)"
        >
          {l}
        </text>
      ))}
    </g>
  );
}

function NodeShape({ node, threats }: { node: Placed; threats: Threat[] }) {
  const { x, y, kind, name } = node;
  const w = NODE_W;
  const h = NODE_H;
  const label = name;
  const sub =
    threats.length > 0
      ? threats.map((t) => `${t.id}: ${t.category}`).join(", ")
      : "Threats: None";

  const fill =
    kind === "external" ? "#f5c2c7" : kind === "datastore" ? "#cfe0f2" : "#c3dbf3";
  const stroke =
    kind === "external" ? "#dc2626" : kind === "datastore" ? "#2f6fb0" : "#2563eb";

  return (
    <g>
      {kind === "external" && (
        <ellipse cx={x} cy={y} rx={w / 2} ry={h / 2} fill={fill} stroke={stroke} strokeWidth={2.4} />
      )}
      {kind === "process" && (
        <rect x={x - w / 2} y={y - h / 2} width={w} height={h} rx={8} fill={fill} stroke={stroke} strokeWidth={2.4} />
      )}
      {kind === "datastore" && (
        <g>
          <path
            d={cylinder(x - w / 2, y - h / 2, w, h)}
            fill={fill}
            stroke={stroke}
            strokeWidth={2.4}
          />
          <ellipse cx={x} cy={y - h / 2 + 9} rx={w / 2} ry={9} fill="none" stroke={stroke} strokeWidth={2.4} />
        </g>
      )}
      <text x={x} y={y - 4} textAnchor="middle" fontSize={14.5} fontWeight={700} fill="#101822" fontFamily="var(--font-slab)">
        {label}
      </text>
      <text
        x={x}
        y={y + 15}
        textAnchor="middle"
        fontSize={10.5}
        fill={threats.length ? STRIDE_META[threats[0].category].token : "#5a6879"}
        fontFamily="var(--font-mono)"
      >
        {sub.length > 30 ? sub.slice(0, 29) + "…" : sub}
      </text>
    </g>
  );
}

function cylinder(x: number, y: number, w: number, h: number) {
  const r = 9;
  return [
    `M${x},${y + r}`,
    `a${w / 2},${r} 0 0 0 ${w},0`,
    `v${h - r * 2}`,
    `a${w / 2},${r} 0 0 1 ${-w},0`,
    `z`,
  ].join(" ");
}
