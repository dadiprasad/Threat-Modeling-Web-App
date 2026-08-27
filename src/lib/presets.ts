import { DfdNode, DfdFlow } from "./threatEngine";

export interface Preset {
  key: string;
  name: string;
  desc: string;
  nodes: DfdNode[];
  flows: DfdFlow[];
}

export const PRESETS: Preset[] = [
  {
    key: "ecommerce",
    name: "E-commerce checkout",
    desc: "Browser → API → DB + external payment gateway.",
    nodes: [
      { id: "fe", name: "Frontend", kind: "external", zone: "Frontend Boundary" },
      { id: "be", name: "Backend", kind: "process", zone: "Backend Boundary" },
      { id: "db", name: "Database", kind: "datastore", zone: "Backend Boundary" },
      { id: "pg", name: "Payment Gateway", kind: "external", zone: "Payment Gateway Boundary" },
    ],
    flows: [
      { id: "f1", from: "fe", to: "be", label: "User Input (PII, Credentials)", protocol: "HTTPS" },
      { id: "f2", from: "be", to: "db", label: "User Data, Orders", protocol: "SQL/TLS" },
      { id: "f3", from: "be", to: "pg", label: "Payment Details", protocol: "HTTPS (TLS 1.3)" },
    ],
  },
  {
    key: "iot",
    name: "IoT telemetry pipeline",
    desc: "Devices → gateway → stream → analytics + cold storage.",
    nodes: [
      { id: "dev", name: "IoT Device", kind: "external", zone: "Field Boundary" },
      { id: "gw", name: "Edge Gateway", kind: "process", zone: "Edge Boundary" },
      { id: "stream", name: "Kafka Stream", kind: "datastore", zone: "Cloud Boundary" },
      { id: "svc", name: "Analytics Service", kind: "process", zone: "Cloud Boundary" },
      { id: "s3", name: "S3 Bucket", kind: "datastore", zone: "Cloud Boundary" },
    ],
    flows: [
      { id: "f1", from: "dev", to: "gw", label: "Sensor Telemetry", protocol: "MQTT/TLS" },
      { id: "f2", from: "gw", to: "stream", label: "Batched Events", protocol: "TCP/TLS" },
      { id: "f3", from: "stream", to: "svc", label: "Event Stream", protocol: "TCP/TLS" },
      { id: "f4", from: "svc", to: "s3", label: "Aggregates", protocol: "HTTPS" },
    ],
  },
  {
    key: "banking",
    name: "Banking API + SSO",
    desc: "Mobile app authenticates via IdP, hits core banking API.",
    nodes: [
      { id: "app", name: "Mobile App", kind: "external", zone: "Client Boundary" },
      { id: "idp", name: "Identity Provider", kind: "external", zone: "IdP Boundary" },
      { id: "api", name: "Banking API", kind: "process", zone: "Core Boundary" },
      { id: "ledger", name: "Ledger DB", kind: "datastore", zone: "Core Boundary" },
      { id: "fraud", name: "Fraud Service", kind: "process", zone: "Core Boundary" },
    ],
    flows: [
      { id: "f1", from: "app", to: "idp", label: "Auth Request (OIDC)", protocol: "HTTPS (OIDC)" },
      { id: "f2", from: "app", to: "api", label: "Signed Transactions", protocol: "HTTPS (mTLS)" },
      { id: "f3", from: "api", to: "ledger", label: "Balance Updates", protocol: "SQL/TLS" },
      { id: "f4", from: "api", to: "fraud", label: "Risk Signals", protocol: "gRPC/mTLS" },
    ],
  },
];
