# Concept Trace — client/ vs Part B

> **Scope**: Part B domain concept (B.1 ubiquitous language · B.3 11 bounded context · B.4 cross-context protocol · B.5 API surface · B.6 storage) mapped to crates in client/; placement rules derived.
> **Pace layer** `[T per P.5]`: concept = 3-5 year semi-stable; this file refreshes when `domain-core`/`proto` adds a new type/contract.
> **Relations**:
> - Part A invariant status → `docs/invariant-trace.md`
> - Verification mechanism (contract test pattern) → `docs/qc-discipline.md`
> - Gate per milestone → `docs/phase-completion-checklist-<X.Y>.md`
>
> **Snapshot**: 2026-06-11 · milestone 1.1 Founding skeleton.
>
> **How to read** (D-00 §4): [H] map + rules; [R] method, T/A, log.

-----
-----

# [H] — For coder/owner

## H.0 — Summary — key decisions

**Placement rules** derived from A.1.4 + Part D §D.2:
- Part B concepts entering client/ **must** belong to `domain-core` (entity types) or `proto` (gRPC/REST contract) — these are **OPEN shared contracts** that control-plane depends on inversely (D.4).
- Vendor-side concepts (Subscription runtime data, TierFeatureSet runtime, vendor governance log) do **NOT** appear in the client repo — they belong to CLOSED control-plane.
- Hybrid concepts (`AdminAccessPolicy`, `JitRequest`, `Pattern4Whitelist`…) — *contract type* goes into `proto` (client API surface); *runtime evaluation* is in control-plane.

**Snapshot 2026-06-11**:
- B.1 ubiquitous language: 8 concept groups → `domain-core` (stub) + `proto` (contract stub).
- B.3 11 bounded contexts: 6 client-touching + 5 NA-client. Verify: NA-client has NO corresponding type/module name in client.
- B.4 8 cross-context protocols: 5 client-touching (Agent-side) + 3 control-plane-only. + Part C `[A]` Org/Workspace protocol (defer).
- B.5 API surface: `proto` skeleton 10 RPC methods + Admin API REST contract.
- B.6 storage: namespace template in `proto`; PostgreSQL/S3 = NA-client.

-----

## H.1 — Placement rules (derived from principles)

| Rule | Enforcing principle | Consequence |
|---|---|---|
| Concept "agent-side runtime state" → `agent-core` | P.1 + A.3.1 hexagonal | State managed in agent crate, does not leak through ports |
| Concept "shared contract between agent ↔ control-plane" → `domain-core`/`proto` | A.1.4 + P.7 | OPEN; control-plane depends inversely (D.4) |
| Concept "crypto primitive / cert chain" → `crypto` | P.1 + intensity Critical | Cite all primitive docs; agent verifies chain client-side |
| Concept "vendor-managed lifecycle runtime" → **NA-client** | A.1.4 + Part D §D.2 | Vendor-side data, no audit surface → CLOSED |
| Concept "Part C `[A]` deferred" (Organization, Workspace runtime) → **DO NOT add** | P.8 + Part C §H.7.2 | Anti-pattern: pre-build before L_subsidiary trigger |

> ⚠️ **Prohibited**: adding vendor-side concepts to `domain-core` "to make it convenient for control-plane to import" — violates A.1.4 (client → control-plane is one-directional: client provides contract, control-plane consumes) + leaks operational IP through public repo.

-----

## H.2 — B.1 Ubiquitous Language → crate

8 concept groups per Part B §B.1.1-§B.1.8:

| B.1.x | Concept | Supporting crate | Status 1.1 |
|---|---|---|---|
| B.1.1 | `Operator`, `ProductLine` | `domain-core` | 🟡 enum stub |
| B.1.1 | `Customer`, `Tenant` | `domain-core` | 🟡 stub (Customer carries `product_line`; Tenant carries `(customer_id, product_line, tenant_id)`) |
| B.1.1 | `Organization`, `Workspace` (A.1.24 defer) | `domain-core` | ✅ **DO NOT add** — correct (anti-pattern Part C §H.7.2) |
| B.1.1 | `Node`, `Service`, `User`, `Admin` | `domain-core` + `crypto` (cert chain) | 🟡 stub |
| B.1.2 | `Tag`, `Role`, `IdentityClaim`, `AAL`, `Policy`/`Decision` | `domain-core` + `proto.Intent`/`Decision` | 🟡 stub |
| B.1.3 | `Tunnel`, `Intent`, `OverlayIP`, `Endpoint` | `agent-core` (state) + `proto` (contract) | 🟡 stub |
| B.1.4 | `NodeTier` 1-4, `DataClassification`, `WorkloadKind` (9 variants), `MeshDeploymentPattern` (A/B/C) | `domain-core` (enum) + `agent-core` (apply pattern) | 🟡 stub |
| B.1.5 | `AuditEvent`, `Block`, `LedgerFamily`, `Witness` | `ledger-client` + `proto.ReportEvent`/`StreamLog` | 🟡 skeleton |
| B.1.6 | `ControlPlaneRole`, `Capability`, `TenantConfig`, `AdminAccessPolicy` | `proto` (Admin API contract) | 🟡 skeleton |
| B.1.7 | `Deployment Mode` (vendor-side runtime) | NA-client | ✅ NA |
| B.1.8 | `Commercial Tier`, `Subscription`, `TierFeatureSet`, `Lifecycle Event` | NA-client (vendor-managed) | ✅ NA |
| B.1.8 | `OrgBillingMode`, `OrgInvoiceRollup`, `OrgLifecycleEvent` (A.1.24 Part C) | NA-client + deferred | ✅ NA + deferred |

**Hardware classification (B.1.4)**: enum platform → hardware tier (T1-T2 Layer 1 mandatory: TPM 2.0 / T2 chip / Secure Enclave / StrongBox / Nitro Enclave / Shielded VM / Confidential VM). `domain-core` defines enum + pre-check tool in `cli` (`mesh-agent precheck --tier <N> --commercial-tier <F>`).

-----

## H.3 — B.3 Bounded Context → client touchpoint

11 contexts per Part B §B.3, 6 client-touching + 5 NA-client:

| Context | Responsibility | Client touchpoint | Status 1.1 |
|---|---|---|---|
| B.3.1 Identity & Enrollment | TenantCA chain, enrollment ceremony, hardware attestation, revoke | `crypto` (cert chain verify) + `proto.Enroll(EnrollmentCompletion)` + ceremony rule "domain change = new enrollment" | 🟡 skeleton |
| B.3.2 Policy & Authorization | Policy block ledger, compile, evaluate Intent | `proto.FetchPolicy` (agent fetch lazy); `proto.SubmitIntent` carries identity_claim | 🟡 skeleton |
| B.3.3 Connection Broker | Resolve Intent → Decision + ephemeral key | `proto.SubmitIntent`/`RefreshGrant` (agent-side client); capability negotiation by agent version | 🟡 skeleton |
| B.3.4 Data Plane (Tunneling) | WireGuard mesh, NAT traversal, overlay IP, mesh deployment pattern | `agent-core` (WireGuard wrapper, tunnel state, Path 2 logic); `domain-core.MeshDeploymentPattern` | 🟡 skeleton (core target milestone 1.1) |
| B.3.5 Inspection (WAF/DLP) | Internal WAF sidecar L7, DLP pattern | **NA-client** (sidecar control-side; open-candidate `[A]` finalized when building milestone 1.2) | ✅ NA |
| B.3.6 Audit & Compliance | NATS → S3 pipeline, redaction at node, witness anchor | `proto.ReportEvent`/`StreamLog`; redaction logic in `agent-core` (per A.1.2) | 🟡 skeleton |
| B.3.7 Tenant Operations | RBAC control-plane, approval workflow, AdminAccessPolicy, JIT elevation | `proto` Admin API contract types (`AdminAccessPolicy`, `JitRequest`) | 🟡 contract skeleton |
| B.3.8 Customer Lifecycle | Signup, tier transition, billing, offboard | **NA-client** (vendor-managed) | ✅ NA |
| B.3.9 Control Plane Access | Vendor role per-PL, 5-layer defense, ceremony VendorRoot | **NA-client** (control-plane) | ✅ NA |
| B.3.10 Release & Version Lifecycle | Single CI pipeline, dual signing, force-upgrade, capability negotiation | Agent update channel + rollback (`agent-daemon`); Cosign verify | 🟡 skeleton |
| B.3.11 Personal Edge Channel | Edge proxy `*.mesh.dev`, signup gate, abuse defense F0/F0-Plus | **NA-client** (vendor edge) | ✅ NA |

**Verify NA-client**: grep negative — `rg "lifecycle_admin|vendor_role|edge_channel|waf_sidecar"` in client crates must = 0 matches. Test at `docs/qc-discipline.md` H.4 pattern.

-----

## H.4 — B.4 Cross-context Protocol

8 protocols per Part B §B.4 + Part C `[A]` Org/Workspace protocol:

| Protocol (B.4.x) | Type | Client touchpoint | Status 1.1 |
|---|---|---|---|
| B.4.1 Intent Resolution (Agent ↔ Broker) | Agent-side | `proto.SubmitIntent` + cross-PL constraint (cert verify fails at TLS) | 🟡 skeleton |
| B.4.2 Enrollment (Tier 1 ceremony) | Agent-side | `proto.Enroll`; hardware attestation field; 3-party signature in block | 🟡 contract skeleton |
| B.4.3 Audit Event Streaming | Agent-side | `proto.ReportEvent`/`StreamLog`; redaction at node | 🟡 skeleton |
| B.4.4 Policy Block Submission | Admin-side | `proto` Admin API `POST /v1/policies` contract | 🟡 contract skeleton |
| B.4.5 Pattern 4 Whitelist Update | Admin-side | `proto` Admin API + `Pattern4Whitelist` type | 🟡 contract skeleton |
| B.4.6 JIT Admin Elevation | Admin-side | `proto` Admin API + `JitRequest` type | 🟡 contract skeleton |
| B.4.7 Tenant Creation | Vendor-side | **NA-client** (VendorAdmin op) | ✅ NA |
| B.4.8 Vendor Ceremony | Vendor-side | **NA-client** (Operator Root rotation) | ✅ NA |
| **Part C `[A]` Org/Workspace** | Deferred | **NOT specified** at milestone 1.1 (anti-pattern Part C §H.7.2) | ✅ deferred |

**Cross-PL constraint** (B.4.1): Broker rejects Intent if source/target differs in PL — trust chains are not interchangeable (A.1.18). Client embodies: agent connects to the correct broker per-PL according to node cert; cert verify fails cross-PL at TLS layer per Part B §B.5.1.

-----

## H.5 — B.5 API Surface

### B.5.1 Agent API (gRPC/Tonic) — lives in `proto` crate

10 RPC methods per Part B §B.5.1:

```
service AgentControl {
  rpc Enroll(EnrollmentCompletion) returns (NodeIdentity);
  rpc Heartbeat(NodeStatus) returns (HeartbeatAck);
  rpc SubmitIntent(Intent) returns (Decision);
  rpc RefreshGrant(GrantRefresh) returns (Decision);
  rpc FetchPolicy(PolicyQuery) returns (PolicyView);
  rpc ReportEvent(AgentEvent) returns (EventAck);
  rpc StreamLog(stream LogEntry) returns (LogStreamAck);
  rpc DeclareWorkload(WorkloadDeclaration) returns (WorkloadAck);
  rpc SubmitAdminAccessIntent(AdminAccessIntent) returns (AdminAccessDecision);
  rpc SubmitJitElevationRequest(JitRequest) returns (JitResponse);
}
```

**Per-PL constraint**: agent connects to Broker endpoint per-PL according to node cert (Personal CA chain → Personal Broker; Enterprise CA chain → Enterprise Broker). Cross-PL verify fails at TLS. Contract test at `docs/qc-discipline.md` Layer 4.

### B.5.2 Admin API (REST + WebSocket/Axum) — contract type in `proto`

Endpoint per tenant, PL inherited. Main surfaces:
- `POST/GET /v1/policies` — policy block submission
- `POST /v1/enrollments` + `/{id}/approve` — enrollment workflow
- `GET/DELETE /v1/nodes[/{id}]` — node management
- `POST/GET/PUT/DELETE /v1/admin-policies[/{id}]` — admin access management
- `POST/GET/PUT/DELETE /v1/pattern4-whitelists[/{id}]` — Pattern 4 whitelist
- `POST/GET /v1/jit-requests[/{id}/approve]` — JIT elevation (Enterprise)
- `POST/GET /v1/nodes/{id}/workload` — workload declaration
- `GET/DELETE /v1/admin-sessions[/{id}[/recording]]` — admin session (F3 Enterprise)

**API host per-PL**: `api.personal.mesh.dev` / `api.enterprise.mesh.dev` (or customer-branded F2 Growth+). Admin auth uses OIDC provider per-PL.

**Part C `[A]` Org-level endpoint** (invoice rollup / org dashboard / Workspace management): NOT specified at milestone 1.1.

-----

## H.6 — B.6 Storage namespace

### B.6.1 NATS subject namespace (client touchpoint)

Template in `proto` crate, enforced via A.1.11:

```
personal.tenant.<tid>.{audit|event|policy|intent}.*
enterprise.tenant.<tid>.{audit|event|policy|intent}.*
```

Agent publishes/subscribes to the correct PL according to node cert. Cross-PL routing does **NOT** exist (separate cluster).

### B.6.2 PostgreSQL + S3

`PostgreSQL` (control-plane RDS) + `S3 layout` (audit/ledger/session-recording bucket per-PL) = **NA-client**. Client touches via API (`proto.ReportEvent` → control-plane → S3), not directly.

### B.6.3 Part C `[A]` Workspace sub-namespace

Proposed `<pl>.tenant.<tid>.ws.<wid>.*` — Part C, NOT specified at milestone 1.1.

-----

## H.7 — Owner actions

1. **Ratify placement rules** (H.1) — sign off that vendor-side concepts do NOT go into the client repo even if "convenient for control-plane import".
2. **Confirm NA-client verification** — grep negative tests sufficiently cover (B.3.5 WAF/B.3.8 lifecycle/B.3.9 control plane/B.3.11 Personal edge); see `docs/qc-discipline.md` H.4.
3. **A.1.24 concept defer = correct** — sign off that `Organization`/`Workspace` runtime types are NOT added to `domain-core` until L_subsidiary fires.
4. **Update cadence** — refresh this file when `proto`/`domain-core` adds a new type/contract; if a concept is added that is not in Part B, Part B must be amended first (SSOT).

-----
-----

# [R] — Verification section

## R1 — Method

**Verification level**: contract-level (concept type exists in `domain-core`/`proto` + signature matches Part B §B.5). Runtime evaluation (broker decide, policy compile) = control-plane scope, cannot be verified in client.

**Mechanism to transition 🟡 → ✅**: contract test passes per pattern `docs/qc-discipline.md` H.2 Layer 4 + marker `QC-concept[B.x.y]`; NA-client verified by grep negative test.

## R2 — T/A markings

- **`[T]`**: 8 concept groups B.1; 11 bounded contexts B.3; 8 protocols B.4; API surface B.5; namespace B.6.3 = full text Part B; placement rules = derived from A.1.4 + Part D §D.2.
- **`[A]`**: 15 items 🟡 — contract skeleton, full signature pending; `OrgBillingMode` + `Workspace` runtime construct = Part C deferred.
- **`[A risk-accepted, owned]`**: A.1.24 deferred concept (correct); B.3.5 WAF open-candidate (finalized at milestone 1.2).

## R3 — Log

- **init** (2026-06-11): reviewed B.1 (8 groups) + B.3 (11 contexts, 6 client-touching + 5 NA) + B.4 (8 protocols + Part C `[A]`) + B.5 (10 RPC + REST surface) + B.6 (NATS namespace + NA-client storage). Snapshot milestone 1.1. Generated from `INVARIANT-COVERAGE.md` H.4 (deleted) during refactor to CP structure.

-----
