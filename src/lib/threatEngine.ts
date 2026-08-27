// STRIDE threat generation engine.
// Given a set of components (nodes) and data flows, it derives trust
// boundaries and produces a numbered, deterministic-but-architecture-specific
// set of threats. Change the architecture -> the threat set and IDs change.

export type NodeKind = "external" | "process" | "datastore";

export type StrideCategory =
  | "Spoofing"
  | "Tampering"
  | "Repudiation"
  | "Information Disclosure"
  | "Denial of Service"
  | "Elevation of Privilege";

export interface DfdNode {
  id: string;
  name: string;
  kind: NodeKind;
  zone: string; // trust zone name
}

export interface DfdFlow {
  id: string;
  from: string; // node id
  to: string; // node id
  label: string; // what moves across
  protocol?: string; // transport/protocol, e.g. HTTPS, mTLS, SQL/TLS
}

export type Severity = "Critical" | "High" | "Medium" | "Low";

// Review workflow state for a finding. Threats are regenerated deterministically,
// so status is tracked by the caller (keyed by threatKey) and merged back in.
export type ThreatStatus = "Open" | "Mitigated" | "Accepted";

export interface Threat {
  id: string; // T1, T2 ...
  category: StrideCategory;
  scope: "flow" | "node" | "boundary";
  targetId: string; // flow id / node id / zone name
  targetLabel: string;
  likelihood: number; // 1-3, from exposure (reachability + boundary crossings)
  impact: number; // 1-3, from data sensitivity + consequence of the STRIDE class
  risk: number; // likelihood × impact, 1-9
  severity: Severity; // risk band derived from the score
  status: ThreatStatus; // review status (Open by default)
  trace: string; // traceability chain: T → element → flow path → boundary
  rationale: string; // description — what/why in this architecture
  mitigation: string;
  securityControls: string; // concrete controls to implement
  owaspAsvs: string; // ASVS verification requirement references
  owaspSamm: string; // SAMM practice references
}

// A stable identity for a threat that survives re-analysis (T-IDs are reassigned
// by risk each run, so they can't key persistent state like review status).
export const threatKey = (t: Pick<Threat, "scope" | "targetId" | "category" | "rationale">) =>
  `${t.scope}:${t.targetId}:${t.category}:${t.rationale}`;

// Confidence we place in whatever sits inside a boundary.
export type TrustLevel = "Untrusted" | "Semi-Trusted" | "Trusted";

export interface TrustBoundary {
  id: string; // TB-01, TB-02 ... for traceability references
  zone: string;
  nodeIds: string[];
  trustLevel: TrustLevel;
  rationale: string; // why this zone carries this trust level
}

export interface ThreatModel {
  boundaries: TrustBoundary[];
  threats: Threat[];
  crossings: Set<string>; // flow ids that cross a boundary
}

export const STRIDE_META: Record<
  StrideCategory,
  { tag: string; token: string; blurb: string }
> = {
  Spoofing: { tag: "S", token: "var(--color-stride-s)", blurb: "Identity impersonation" },
  Tampering: { tag: "T", token: "var(--color-stride-t)", blurb: "Unauthorized modification" },
  Repudiation: { tag: "R", token: "var(--color-stride-r)", blurb: "Deniable actions" },
  "Information Disclosure": { tag: "I", token: "var(--color-stride-i)", blurb: "Data exposure" },
  "Denial of Service": { tag: "D", token: "var(--color-stride-d)", blurb: "Availability loss" },
  "Elevation of Privilege": { tag: "E", token: "var(--color-stride-e)", blurb: "Privilege escalation" },
};

// Analyst impact rating (per scenario) → impact axis value on a 1-3 scale.
function impactSeed(rating: Severity): number {
  return rating === "Critical" ? 3 : rating === "Low" ? 1 : 2;
}

// Map a likelihood × impact score to a risk band on a standard 3×3 matrix
// (scores are 1, 2, 3, 4, 6, or 9). Critical is reserved for max impact × max
// exposure so the ranking stays meaningful instead of everything reading red.
export function riskBand(risk: number): Severity {
  if (risk >= 9) return "Critical";
  if (risk >= 6) return "High";
  if (risk >= 3) return "Medium";
  return "Low";
}

export const SEVERITY_META: Record<Severity, { token: string; rank: number }> = {
  Critical: { token: "var(--color-stride-d)", rank: 0 },
  High: { token: "var(--color-stride-e)", rank: 1 },
  Medium: { token: "var(--color-stride-t)", rank: 2 },
  Low: { token: "var(--color-fg-dim)", rank: 3 },
};

const MITIGATIONS: Record<StrideCategory, string> = {
  Spoofing: "Enforce strong mutual authentication (mTLS / OAuth2) and verify identity claims.",
  Tampering: "Sign and validate payloads; apply integrity checks and least-privilege writes.",
  Repudiation: "Emit tamper-evident audit logs with per-actor attribution and timestamps.",
  "Information Disclosure": "Encrypt in transit and at rest; minimize and mask sensitive fields.",
  "Denial of Service": "Apply rate limiting, quotas, timeouts and autoscaling with backpressure.",
  "Elevation of Privilege": "Enforce authorization checks, sandboxing and role isolation on every call.",
};

// Concrete, mappable controls and framework references per STRIDE category so
// each finding carries the same depth a real assessment would document.
const SECURITY_CONTROLS: Record<StrideCategory, string> = {
  Spoofing: "Terminate TLS with certificate pinning; issue short-lived tokens (OAuth2/OIDC) and enforce mTLS between services. On AWS, front the edge with WAF + Cognito/IAM auth.",
  Tampering: "HMAC- or signature-sign requests, validate schemas server-side, and enable object integrity (e.g. S3 checksums, DB constraints, WORM logs).",
  Repudiation: "Enable AWS CloudTrail and application audit logs with per-actor IDs and timestamps; ship to an append-only, integrity-protected store (CloudWatch/OpenSearch).",
  "Information Disclosure": "Encrypt in transit (TLS 1.2+) and at rest (KMS); tokenize/mask PII and card data; scope responses to least data and apply field-level authorization.",
  "Denial of Service": "Enable AWS Shield + WAF rate rules, API Gateway throttling and quotas, request timeouts, and autoscaling with circuit breakers/backpressure.",
  "Elevation of Privilege": "Apply least-privilege IAM roles, per-endpoint authorization checks, and workload isolation (separate execution roles / containers); deny by default.",
};

const OWASP_ASVS: Record<StrideCategory, string> = {
  Spoofing: "V2.1 - Password & credential security; V2.7 - Out-of-band verifiers; V3.5 - Token-based session management.",
  Tampering: "V5.1 - Input validation; V5.2 - Sanitization & sandboxing; V13.2 - RESTful web service integrity.",
  Repudiation: "V7.1 - Log content requirements; V7.2 - Log processing & integrity.",
  "Information Disclosure": "V6.2 - Algorithms & encryption at rest; V9.1 - Communications security (TLS); V8.2 - Client-side data protection.",
  "Denial of Service": "V11.1 - Business logic security (anti-automation); V13.4 - GraphQL/resource limits; V4.2 - Operation-level access control.",
  "Elevation of Privilege": "V4.1 - General access control design; V4.3 - Other access control (least privilege); V1.4 - Access control architecture.",
};

const OWASP_SAMM: Record<StrideCategory, string> = {
  Spoofing: "Design › Security Architecture L2; Operations › Environment Management L2 - harden authentication.",
  Tampering: "Implementation › Secure Build L2; Verification › Security Testing L2 - validate integrity controls.",
  Repudiation: "Operations › Security Operations L2 - enable audit logging; Incident Management L2 - monitor logs.",
  "Information Disclosure": "Design › Threat Assessment L2; Operations › Environment Management L2 - protect data stores.",
  "Denial of Service": "Operations › Incident Management L2 - detect/respond; Environment Management L2 - resilience & scaling.",
  "Elevation of Privilege": "Design › Security Architecture L3; Verification › Security Testing L2 - authorization testing.",
};

type NodeRole = "actor" | "dependency" | "process" | "datastore";

// External nodes split into untrusted *actors* (users/clients that call in) and
// trusted third-party *dependencies* (payment gateways, SSO/IdP) that we call out to.
const roleOf = (n: DfdNode): NodeRole => {
  if (n.kind === "process") return "process";
  if (n.kind === "datastore") return "datastore";
  return /\b(pay|payment|gateway|stripe|paypal|sso|idp|third|external|partner|vendor)\b/i.test(n.name)
    ? "dependency"
    : "actor";
};

// Classify what actually moves across a flow from its data label, so findings
// and severity reflect the payload — not every flow carries regulated data.
function dataSensitivity(label: string): { sensitive: boolean; kind: string } {
  const l = label.toLowerCase();
  if (/\b(card|pan|cvv|payment|credit)s?\b/.test(l)) return { sensitive: true, kind: "cardholder data" };
  if (/\b(credential|password|secret|token|api key|private key|auth|oauth|oidc|login|session)s?\b/.test(l)) return { sensitive: true, kind: "credentials/secrets" };
  if (/\b(pii|personal|ssn|health|phi|kyc|identity|user input|user data)s?\b/.test(l)) return { sensitive: true, kind: "personal data (PII)" };
  if (/\b(balance|transaction|ledger|order|financial|account|invoice)s?\b/.test(l)) return { sensitive: true, kind: "financial records" };
  return { sensitive: false, kind: "operational data" };
}

function cap(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function flowLabel(nodes: DfdNode[], f: DfdFlow) {
  const a = nodes.find((n) => n.id === f.from)?.name ?? "?";
  const b = nodes.find((n) => n.id === f.to)?.name ?? "?";
  return `${a} → ${b}`;
}

export function analyze(nodes: DfdNode[], flows: DfdFlow[]): ThreatModel {
  const nodeByIdEarly = (id: string) => nodes.find((n) => n.id === id);
  // Trust boundaries = distinct zones with >=1 node. Each gets a stable TB-nn
  // reference plus a derived trust level + rationale for architect review.
  const zoneOrder: string[] = [];
  for (const n of nodes) if (!zoneOrder.includes(n.zone)) zoneOrder.push(n.zone);
  const pad2 = (i: number) => String(i).padStart(2, "0");
  const boundaries: TrustBoundary[] = zoneOrder.map((zone, i) => {
    const nodeIds = nodes.filter((n) => n.zone === zone).map((n) => n.id);
    const roles = nodeIds.map((id) => roleOf(nodeByIdEarly(id)!));
    let trustLevel: TrustLevel;
    let rationale: string;
    if (roles.includes("actor")) {
      trustLevel = "Untrusted";
      rationale = "Hosts external actors/clients that call in; asserted identities cannot be verified.";
    } else if (roles.includes("dependency")) {
      trustLevel = "Semi-Trusted";
      rationale = "Contains third-party dependencies outside our administrative control.";
    } else {
      trustLevel = "Trusted";
      rationale = "Internal processes/data stores operated under our own control.";
    }
    return { id: `TB-${pad2(i + 1)}`, zone, nodeIds, trustLevel, rationale };
  });
  const boundaryRef = new Map(boundaries.map((b) => [b.zone, b]));
  // Stable F-nn display references for flows, used in traceability chains.
  const flowRef = new Map(flows.map((f, i) => [f.id, `F${pad2(i + 1)}`]));

  const zoneOf = (id: string) => nodes.find((n) => n.id === id)?.zone;
  const crossings = new Set<string>();
  for (const f of flows) {
    if (zoneOf(f.from) !== zoneOf(f.to)) crossings.add(f.id);
  }

  const threats: Threat[] = [];
  // Dedup only EXACT duplicate scenarios (same element, category AND rationale).
  // Distinct scenarios that happen to share a STRIDE category — e.g. business-data
  // tampering vs in-transit integrity tampering on the same flow — are both kept,
  // because collapsing them by letter would drop real, separately-mitigated threats.
  const seenThreat = new Set<string>();
  // The 5th argument is the analyst impact rating for the scenario; it seeds the
  // impact axis. Likelihood (exposure) and the final risk band are computed in a
  // post-processing pass once every threat and its target context are known.
  const add = (
    category: StrideCategory,
    scope: Threat["scope"],
    targetId: string,
    targetLabel: string,
    impactRating: Severity,
    rationale: string,
    refs?: Partial<Pick<Threat, "mitigation" | "securityControls" | "owaspAsvs" | "owaspSamm">>,
  ) => {
    const key = `${scope}:${targetId}:${category}:${rationale}`;
    if (seenThreat.has(key)) return;
    seenThreat.add(key);
    threats.push({
      id: "", // assigned after prioritization
      category,
      scope,
      targetId,
      targetLabel,
      likelihood: 0, // computed post-hoc
      impact: impactSeed(impactRating),
      risk: 0, // computed post-hoc
      severity: impactRating, // replaced by the risk band post-hoc
      status: "Open",
      trace: "", // built post-hoc once T-IDs and refs are known
      rationale,
      mitigation: refs?.mitigation ?? MITIGATIONS[category],
      securityControls: refs?.securityControls ?? SECURITY_CONTROLS[category],
      owaspAsvs: refs?.owaspAsvs ?? OWASP_ASVS[category],
      owaspSamm: refs?.owaspSamm ?? OWASP_SAMM[category],
    });
  };

  const processes = nodes.filter((n) => n.kind === "process");
  const externals = nodes.filter((n) => n.kind === "external");
  const stores = nodes.filter((n) => n.kind === "datastore");
  const nodeById = (id: string) => nodes.find((n) => n.id === id);

  // Threats are derived from what each flow actually connects, not just from
  // whether it crosses a boundary. The role of each endpoint decides which
  // STRIDE categories are realistic for that flow.
  for (const f of flows) {
    const from = nodeById(f.from);
    const to = nodeById(f.to);
    if (!from || !to) continue;
    const label = flowLabel(nodes, f);
    const crosses = crossings.has(f.id);
    const fromRole = roleOf(from);
    const toRole = roleOf(to);
    // What the flow carries drives disclosure risk and its severity.
    const data = dataSensitivity(f.label);
    const discSev: Severity = data.sensitive ? "Critical" : "Medium";

    if (toRole === "dependency") {
      // Outbound call to a trusted third-party (payment gateway, SSO, etc.).
      // The risk is leaking data to / being deceived by the remote endpoint —
      // NOT availability, since we are the caller, not an exposed target.
      add("Information Disclosure", "flow", f.id, label, discSev,
        `${cap(data.kind)} ("${f.label}") sent to the external ${to.name} can be exposed in transit or over-shared with the third party.`,
        {
          securityControls: `Use TLS 1.3 and OAuth 2.0 / scoped API tokens for the ${to.name} API; never log full payloads; tokenize card/PII data.`,
          owaspAsvs: "V9.1.1 - Verify secure communication; V13.2.1 - Verify API security.",
        });
      add("Tampering", "flow", f.id, label, "High",
        `Request parameters (amounts, identifiers, scopes) to ${to.name} can be altered before dispatch without server-side integrity checks.`);
      add("Tampering", "flow", f.id, label, "High",
        `Without signed requests, the payload to ${to.name} can be altered in transit (MITM) between the server and the third party.`);
      add("Spoofing", "flow", f.id, label, "High",
        `A man-in-the-middle can impersonate ${to.name} if its certificate/endpoint is not pinned and verified.`);
      add("Repudiation", "flow", f.id, label, "Medium",
        `Without signed receipts, transactions with ${to.name} can later be disputed or denied.`);
    } else if (fromRole === "actor") {
      // Inbound edge: an untrusted external actor calling an exposed process.
      // This is the classic attack surface — spoofing, two distinct tampering
      // vectors (business data vs in-transit integrity), DoS, and leakage.
      add("Spoofing", "flow", f.id, label, "Critical",
        `${from.name} identity is unverified when calling ${to.name} across a trust boundary.`);
      add("Tampering", "flow", f.id, label, "High",
        `${from.name} can modify business data (e.g. prices, quantities, totals, hidden fields) to bypass ${to.name} server-side validation.`);
      add("Tampering", "flow", f.id, label, "High",
        `Without message integrity, the payload between ${from.name} and ${to.name} can be altered in transit (MITM) before it reaches the server.`);
      add("Denial of Service", "flow", f.id, label, "Medium",
        `${to.name} is a publicly reachable edge and can be flooded by untrusted callers.`);
      add("Information Disclosure", "flow", f.id, label, data.sensitive ? "High" : "Medium",
        `Responses from ${to.name} may return more ${data.kind} ("${f.label}") than ${from.name} is authorized to see.`);
      add("Elevation of Privilege", "flow", f.id, label, "High",
        `Tampered or forged requests from ${from.name} may invoke privileged ${to.name} operations without proper authorization checks.`);
    } else if (to.kind === "datastore") {
      // Write path into persistence: integrity, confidentiality AND the
      // accountability (repudiation) of the business actions being recorded.
      add("Repudiation", "flow", f.id, label, "Medium",
        `Actions persisted to ${to.name} (e.g. orders, transactions) can later be denied if there is no per-actor, tamper-evident audit trail.`,
        {
          securityControls: `Use AWS CloudTrail plus application audit logs with actor IDs and timestamps; write to an append-only / integrity-protected store.`,
          owaspAsvs: "V7.1.1 - Verify logging controls; V7.2.1 - Verify log integrity.",
        });
      add("Information Disclosure", "flow", f.id, label, discSev,
        `${cap(data.kind)} ("${f.label}") persisted to ${to.name} can be exposed in transit or at rest if not encrypted.`,
        {
          securityControls: `Enable TLS in transit and AES-256 field/column encryption at rest in ${to.name}; manage keys in KMS and restrict decrypt permissions.`,
          owaspAsvs: "V9.1.1 - Verify secure communication; V6.2.1 - Verify data-at-rest encryption.",
        });
      add("Tampering", "flow", f.id, label, crosses ? "High" : "Medium",
        `Writes from ${from.name} into ${to.name} can corrupt records or inject data without integrity constraints and input validation.`,
        {
          securityControls: `Apply parameterized queries, schema/constraint validation and HMAC-SHA256 integrity checks on critical records.`,
          owaspAsvs: "V5.1.4 - Verify data integrity; V5.3.4 - Verify parameterized queries.",
        });
      if (crosses)
        add("Spoofing", "flow", f.id, label, "High",
          `Connection to ${to.name} crosses a boundary and may accept unauthenticated clients.`);
    } else if (from.kind === "datastore") {
      // Read path out of persistence.
      add("Information Disclosure", "flow", f.id, label, discSev,
        `Query results from ${from.name} (${data.kind}) can expose more records to ${to.name} than the request is authorized for.`);
    } else {
      // Internal service-to-service flow.
      add("Repudiation", "flow", f.id, label, "Low",
        `Actions between ${from.name} and ${to.name} lack non-repudiable, per-actor evidence.`);
      add("Information Disclosure", "flow", f.id, label, data.sensitive ? (crosses ? "High" : "Medium") : "Low",
        `${cap(data.kind)} ("${f.label}") traverses the internal path from ${from.name} to ${to.name} and may be captured.`);
      if (crosses)
        add("Spoofing", "flow", f.id, label, "High",
          `${from.name} → ${to.name} crosses a trust boundary without mutual authentication.`);
    }
  }

  // Processes execute privileged logic and are escalation targets.
  for (const p of processes) {
    add("Elevation of Privilege", "node", p.id, p.name, "High",
      `${p.name} mediates access and runs privileged logic that can be abused to gain higher rights.`);
  }
  // Data stores hold persisted, high-value data at rest.
  for (const s of stores) {
    add("Information Disclosure", "node", s.id, s.name, "Critical",
      `${s.name} persists high-value data and is a prime exfiltration target if access controls fail.`);
    add("Tampering", "node", s.id, s.name, "High",
      `Records in ${s.name} can be altered at rest without integrity monitoring or backups.`);
  }
  // External human/client actors are inherently spoofable.
  for (const e of externals) {
    if (roleOf(e) === "actor")
      add("Spoofing", "node", e.id, e.name, "Medium",
        `${e.name} is an external actor whose asserted identity cannot be fully trusted.`);
  }
  // Perimeters admit callers claiming trusted identities; zones that host a
  // process also carry config/secret/code-integrity (tampering) risk.
  for (const b of boundaries) {
    add("Spoofing", "boundary", b.zone, b.zone, "Medium",
      `The ${b.zone} perimeter may admit callers asserting trusted identities without cross-boundary verification.`,
      {
        securityControls: "Enforce mutual TLS with client certificates and validate every cross-boundary request.",
        owaspAsvs: "V2.1.3 - Verify boundary authentication; V13.2.1 - Verify API security.",
      });
    const hasProcess = b.nodeIds.some((id) => nodeById(id)?.kind === "process");
    if (hasProcess)
      add("Tampering", "boundary", b.zone, b.zone, "Medium",
        `Configuration, secrets or deployed code within the ${b.zone} can be tampered with if internal integrity controls and least-privilege are weak.`,
        {
          securityControls: "Apply SHA-256 integrity/checksum verification on artifacts and config, secret management (KMS/Secrets Manager), and secure-coding review.",
          owaspAsvs: "V5.1.3 - Verify input validation; V5.3.5 - Verify secure coding / deserialization.",
        });
  }

  // ---- Risk scoring: likelihood × impact -----------------------------------
  // Impact is seeded from the analyst rating (and reflects data sensitivity for
  // confidentiality/integrity threats). Likelihood is derived purely from
  // exposure: how reachable the element is by untrusted parties and whether the
  // interaction crosses a trust boundary.
  const flowById = (id: string) => flows.find((f) => f.id === id);
  for (const t of threats) {
    let likelihood = 1;
    if (t.scope === "flow") {
      const f = flowById(t.targetId);
      const from = f && nodeById(f.from);
      const to = f && nodeById(f.to);
      const crosses = f ? crossings.has(f.id) : false;
      // Reachable by an untrusted party if it originates from an external actor
      // or terminates at a third-party dependency outside our control.
      const externalReach = (from && roleOf(from) === "actor") || (to && roleOf(to) === "dependency");
      if (crosses) likelihood += 1;
      if (externalReach) likelihood += 1;
    } else if (t.scope === "node") {
      const n = nodeById(t.targetId);
      const r = n ? roleOf(n) : "process";
      // External actors are the most exposed; internal stores the least.
      likelihood = r === "actor" ? 3 : n?.kind === "datastore" ? 1 : 2;
    } else {
      // Boundary perimeters are, by definition, the exposure surface.
      likelihood = 2;
    }
    t.likelihood = Math.min(3, Math.max(1, likelihood));
    t.impact = Math.min(3, Math.max(1, t.impact));
    t.risk = t.likelihood * t.impact;
    t.severity = riskBand(t.risk);
  }

  // Prioritize by risk score (desc), tie-broken by impact then likelihood, then
  // assign T-IDs so the numbering reflects priority — T1 is the top risk.
  threats.sort((a, b) => b.risk - a.risk || b.impact - a.impact || b.likelihood - a.likelihood);
  threats.forEach((t, i) => (t.id = `T${i + 1}`));

  // Traceability: every finding links back through the model so a reviewer can
  // follow T-ID → element → flow path → trust boundary, not just "AI said so".
  const tbFor = (zone?: string) => (zone ? boundaryRef.get(zone) : undefined);
  for (const t of threats) {
    if (t.scope === "flow") {
      const f = flowById(t.targetId);
      const from = f && nodeById(f.from);
      const to = f && nodeById(f.to);
      const ref = f ? flowRef.get(f.id) : undefined;
      const fromTb = tbFor(from?.zone);
      const toTb = tbFor(to?.zone);
      const tbChain =
        fromTb && toTb && fromTb.id !== toTb.id
          ? `${fromTb.id} → ${toTb.id}`
          : toTb?.id ?? fromTb?.id ?? "—";
      t.trace = `${t.id} → ${ref ?? "flow"} (${from?.name ?? "?"} → ${to?.name ?? "?"}) → ${tbChain}`;
    } else if (t.scope === "node") {
      const n = nodeById(t.targetId);
      const tb = tbFor(n?.zone);
      t.trace = `${t.id} → ${n?.name ?? t.targetLabel} → ${tb ? `${tb.id} (${tb.zone})` : "—"}`;
    } else {
      const tb = tbFor(t.targetId);
      const members = tb ? tb.nodeIds.map((id) => nodeById(id)?.name ?? id).join(", ") : "";
      t.trace = `${t.id} → ${tb ? `${tb.id} (${tb.zone})` : t.targetLabel}${members ? ` → [${members}]` : ""}`;
    }
  }

  return { boundaries, threats, crossings };
}

// ---- relationship-aware free-text parser ------------------------------------
// This is a deterministic, fully-offline parser. It does NOT "understand" text
// like an LLM, but it goes well beyond keyword-in-order matching:
//   1. it recognises a broad domain lexicon (web, cloud, enterprise/ERP, OT),
//   2. it infers DIRECTED relationships from verbs ("sends to" vs "reads from")
//      per clause, producing a real topology rather than a straight line, and
//   3. it reports what it could not classify, so missed components are visible.

interface LexEntry {
  rx: RegExp;
  name?: string; // canonical display name; omit to derive from the matched text
  kind: NodeKind;
  zone?: string; // trust zone hint
}

// Order matters: more specific / multi-word entries first so they claim their
// span before a broader entry can match a substring.
const LEXICON: LexEntry[] = [
  // --- OT / industrial ---
  { rx: /\bplant\s+operator\b/i, name: "Plant Operator", kind: "external", zone: "Enterprise Boundary" },
  { rx: /\b(scada)\b/i, name: "SCADA", kind: "process", zone: "OT Boundary" },
  { rx: /\b(plc|rtu)\b/i, name: "PLC", kind: "process", zone: "OT Boundary" },
  { rx: /\b(mes)\b/i, name: "MES", kind: "process", zone: "OT Boundary" },
  { rx: /\bhistorian\b/i, name: "Historian", kind: "datastore", zone: "OT Boundary" },
  { rx: /\b(integration\s+server|middleware|esb|message\s+broker|service\s+bus)\b/i, name: "Integration Server", kind: "process", zone: "Integration Boundary" },
  { rx: /\b(sap|erp)\b/i, name: "SAP / ERP", kind: "datastore", zone: "Enterprise Boundary" },
  { rx: /\b(corporate\s+network|enterprise\s+network|internal\s+network|office\s+network|lan)\b/i, name: "Corporate Network", kind: "process", zone: "Corporate Network Boundary" },
  { rx: /\b(dmz)\b/i, name: "DMZ", kind: "process", zone: "DMZ Boundary" },
  { rx: /\b(jump\s+host|bastion(?:\s+host)?)\b/i, name: "Jump Host", kind: "process", zone: "DMZ Boundary" },
  // --- cloud / third-party dependencies ---
  { rx: /\b(cloud\s+analytics(?:\s+platform)?|analytics\s+platform|cloud\s+platform|cloud\s+service|data\s+lake|cloud)\b/i, name: "Cloud Analytics Platform", kind: "external", zone: "Cloud Boundary" },
  { rx: /\b(payment\s+gateway|payment\s+processor|payment|stripe|paypal|adyen|braintree)\b/i, name: "Payment Gateway", kind: "external", zone: "Payment Gateway Boundary" },
  { rx: /\b(identity\s+provider|idp|sso|oauth\s+provider|okta|auth0|keycloak|cognito)\b/i, name: "Identity Provider", kind: "external", zone: "IdP Boundary" },
  { rx: /\b(third[\s-]?party|partner|vendor|supplier|external\s+service)\b/i, kind: "external" },
  // --- datastores ---
  { rx: /\b(data\s+warehouse|warehouse|redshift|snowflake|bigquery)\b/i, name: "Data Warehouse", kind: "datastore" },
  { rx: /\b(postgres(?:ql)?|mysql|mariadb|oracle|mongo(?:db)?|dynamodb|sql\s+server|database|db|datastore)\b/i, name: "Database", kind: "datastore" },
  { rx: /\b(redis|memcached|cache)\b/i, name: "Cache", kind: "datastore" },
  { rx: /\b(s3|blob\s+storage|object\s+storage|bucket)\b/i, name: "Object Storage", kind: "datastore" },
  { rx: /\b(kafka|rabbitmq|sqs|pub\/?sub|message\s+queue|queue|topic)\b/i, name: "Message Queue", kind: "datastore" },
  // --- generic external actors ---
  { rx: /\b(mobile\s+app|web\s+app|browser|front[\s-]?end|customer|end[\s-]?user|client|user)\b/i, name: "Client", kind: "external" },
  { rx: /\b(operator|technician|engineer|administrator|admin|employee|staff|analyst)\b/i, name: "Operator", kind: "external", zone: "Enterprise Boundary" },
  // --- processes / services ---
  { rx: /\b(api\s+gateway|api|backend|back[\s-]?end|micro[\s-]?service|web\s+service|service|server|application|app\s+server|worker|lambda|function|authentication\s+service|auth\s+service|auth)\b/i, name: "Backend Service", kind: "process" },
  { rx: /\b(load\s+balancer|reverse\s+proxy|proxy|firewall|waf|gateway)\b/i, name: "Gateway", kind: "process" },
];

// Verbs that imply the SUBJECT pulls data IN from the object (object → subject).
const INBOUND = /\b(retrieves?|reads?|gets?|pulls?|fetches?|receives?|imports?|consumes?|queries|loads?|downloads?|subscribes?)\b/i;
// Verbs that imply the SUBJECT pushes data OUT to the object (subject → object).
const OUTBOUND = /\b(sends?|writes?|pushes?|posts?|publishes?|uploads?|transmits?|forwards?|submits?|provides?|stores?|exports?|calls?|invokes?|accesses?|connects?|communicates?|integrates?|talks?|uses?|authenticates?|logs?|routes?|passes?)\b/i;
const VERB_SRC = `${INBOUND.source}|${OUTBOUND.source}`;

// Single monotonic counter shared across the whole app so parser-generated ids,
// preset ids and manually-added ids can never collide (which would produce
// duplicate React keys). Starts above the hardcoded preset id range (f1..f4)
// and is never reset — ids stay globally unique for the session.
let uid = 1000;
export const makeId = (prefix: string) => `${prefix}${++uid}`;
const nid = () => makeId("n");
const fid = () => makeId("f");

interface Hit { entry: LexEntry; index: number; text: string }

// Find every non-overlapping lexicon match in a clause, left to right.
function findHits(sentence: string): Hit[] {
  const claimed: [number, number][] = [];
  const hits: Hit[] = [];
  for (const entry of LEXICON) {
    const re = new RegExp(entry.rx.source, "gi");
    let m: RegExpExecArray | null;
    while ((m = re.exec(sentence))) {
      const start = m.index;
      const end = start + m[0].length;
      if (claimed.some(([cs, ce]) => start < ce && end > cs)) continue;
      claimed.push([start, end]);
      hits.push({ entry, index: start, text: m[0] });
    }
  }
  return hits.sort((a, b) => a.index - b.index);
}

// Split a clause into verb-governed phrases: each spans from one direction verb
// to the next, so the objects after "sends" are handled separately from "reads".
function verbPhrases(sentence: string): { verb: string; start: number; end: number; text: string }[] {
  const re = new RegExp(VERB_SRC, "gi");
  const verbs: { word: string; idx: number }[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(sentence))) verbs.push({ word: m[0], idx: m.index });
  return verbs.map((v, i) => {
    const end = i + 1 < verbs.length ? verbs[i + 1].idx : sentence.length;
    return { verb: v.word, start: v.idx, end, text: sentence.slice(v.idx, end) };
  });
}

// Pull a human data label out of a phrase (the noun phrase between the verb and
// its preposition), used to drive data-sensitivity scoring. Falls back to "Data".
function dataLabelFrom(phraseText: string, verb: string): string {
  const after = phraseText.slice(verb.length);
  const m = after.match(/^\s*(?:the\s+|a\s+|an\s+|some\s+|selected\s+|all\s+|its\s+)*([\w\s-]+?)\s*\b(?:from|to|via|through|over|with|into|for|and)\b/i);
  const label = (m ? m[1] : "").trim();
  if (!label || label.length > 40) return "Data";
  // If the "label" is actually a recognised component, it isn't a data payload.
  if (LEXICON.some((e) => e.rx.test(label))) return "Data";
  return cap(label);
}

export interface ParseResult {
  nodes: DfdNode[];
  flows: DfdFlow[];
  unrecognized: string[]; // component-like nouns the parser could not classify
}

// Best-effort parse of a free-form description into a directed component graph.
export function parseDescription(text: string): ParseResult | null {
  const cleaned = text.replace(/\s+/g, " ").trim();
  if (!cleaned) return null;

  const sentences = cleaned.split(/[.;\n]+|(?:->|→|=>)/).map((s) => s.trim()).filter(Boolean);
  const nodesByName = new Map<string, DfdNode>();
  const nodeFor = (hit: Hit): DfdNode => {
    const name = hit.entry.name ?? titleCase(hit.text);
    const key = name.toLowerCase();
    let n = nodesByName.get(key);
    if (!n) {
      n = { id: nid(), name, kind: hit.entry.kind, zone: hit.entry.zone ?? zoneFor(name, hit.entry.kind) };
      nodesByName.set(key, n);
    }
    return n;
  };

  const edges: { from: string; to: string; label: string }[] = [];
  const edgeSeen = new Set<string>();
  const addEdge = (from: string, to: string, label: string) => {
    if (from === to) return;
    const k = `${from}>${to}`;
    if (edgeSeen.has(k)) return;
    edgeSeen.add(k);
    edges.push({ from, to, label: label || "Data" });
  };

  const unrecognized = new Set<string>();
  let carried: DfdNode | null = null;

  for (const sent of sentences) {
    const hits = findHits(sent);
    collectUnrecognized(sent, hits, unrecognized);
    if (hits.length === 0) continue;
    // Materialise a node for every recognised component in the clause.
    hits.forEach(nodeFor);

    const firstVerbIdx = sent.search(new RegExp(VERB_SRC, "i"));
    const startsWithComponent = hits[0].index < (firstVerbIdx < 0 ? Infinity : firstVerbIdx);
    const subject: DfdNode | null = startsWithComponent ? nodeFor(hits[0]) : carried;
    const subjectIndex = startsWithComponent ? hits[0].index : -1;

    const phrases = verbPhrases(sent);
    if (!subject || phrases.length === 0) {
      // No verb / no subject context — connect recognised components in order
      // (graceful fallback, same as the old behaviour) and carry the last one.
      let prev: DfdNode | null = subject;
      for (const h of hits) {
        if (h.index === subjectIndex) continue;
        const n = nodeFor(h);
        if (prev) addEdge(prev.id, n.id, "Data");
        prev = n;
      }
      carried = prev ?? carried;
      continue;
    }

    for (const ph of phrases) {
      const objs = hits.filter((h) => h.index >= ph.start && h.index < ph.end && h.index !== subjectIndex);
      if (objs.length === 0) continue;
      const inbound = INBOUND.test(ph.verb) || /\bfrom\b/i.test(ph.text);
      const label = dataLabelFrom(ph.text, ph.verb);
      const chain = objs.map(nodeFor);
      if (inbound) {
        // object(s) → … → subject  (data is pulled IN)
        let prev = chain[0];
        for (let i = 1; i < chain.length; i++) { addEdge(prev.id, chain[i].id, label); prev = chain[i]; }
        addEdge(prev.id, subject.id, label);
      } else {
        // subject → object(s)  (data is pushed OUT)
        let prev = subject;
        for (const n of chain) { addEdge(prev.id, n.id, label); prev = n; }
      }
    }
    carried = subject;
  }

  const nodes = [...nodesByName.values()];
  if (nodes.length < 2) return null;
  // If nothing linked up (e.g. a bare comma list), fall back to a chain.
  if (edges.length === 0)
    for (let i = 0; i < nodes.length - 1; i++) addEdge(nodes[i].id, nodes[i + 1].id, "Data");

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const flows: DfdFlow[] = edges.map((e) => ({
    id: fid(),
    from: e.from,
    to: e.to,
    label: e.label,
    protocol: inferProtocol(byId.get(e.from), byId.get(e.to)),
  }));
  return { nodes, flows, unrecognized: [...unrecognized].slice(0, 8) };
}

// Flag component-like nouns (infrastructure suffixes or acronyms) that were NOT
// recognised, so a missed component is surfaced rather than silently dropped.
function collectUnrecognized(sentence: string, hits: Hit[], out: Set<string>) {
  const claimed = hits.map((h) => [h.index, h.index + h.text.length] as [number, number]);
  const re = /\b([A-Za-z][\w-]*(?:\s+[A-Za-z][\w-]*){0,2}\s+(?:system|platform|service|server|gateway|database|datastore|store|app|application|broker|bus|portal|engine|controller|network|module|component|host|cluster|node))\b|\b[A-Z]{2,6}\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(sentence))) {
    const start = m.index;
    const end = start + m[0].length;
    if (claimed.some(([cs, ce]) => start < ce && end > cs)) continue;
    const term = m[0].trim();
    if (term.length < 2) continue;
    if (/^(the|and|from|to|via|over|with|into)$/i.test(term)) continue;
    out.add(term);
  }
}

// Best-effort default protocol from the endpoint kinds, editable afterwards.
function inferProtocol(from?: DfdNode, to?: DfdNode): string {
  if (!from || !to) return "HTTPS";
  if (to.kind === "datastore" || from.kind === "datastore") return "TCP/TLS";
  if (to.kind === "external" || from.kind === "external") return "HTTPS";
  return "HTTPS (internal)";
}

function titleCase(s: string) {
  return s
    .replace(/[-\s]+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function zoneFor(name: string, kind: NodeKind): string {
  if (kind === "external") return `${titleCase(name)} Boundary`;
  if (kind === "datastore") return "Backend Boundary";
  return "Backend Boundary";
}
