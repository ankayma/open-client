# Concept Trace — client/ vs Part B

> **Scope**: Part B domain concept (B.1 ubiquitous language · B.3 11 bounded context · B.4 cross-context protocol · B.5 API surface · B.6 storage) map sang crate trong client/; suy dẫn quy tắc placement.
> **Pace layer** `[T per P.5]`: concept = 3-5 năm semi-stable; file này refresh khi `domain-core`/`proto` add type/contract mới.
> **Quan hệ**:
> - Trạng thái invariant Part A → `docs/invariant-trace.md`
> - Cơ chế verify (contract test pattern) → `docs/qc-discipline.md`
> - Gate per milestone → `docs/phase-completion-checklist-<X.Y>.md`
>
> **Snapshot**: 2026-06-11 · milestone 1.1 Founding skeleton.
>
> **Cách đọc** (D-00 §4): [H] map + quy tắc; [R] method, T/A, log.

-----
-----

# [H] — Dành cho coder/owner

## H.0 — Tóm tắt chốt trước

**Quy tắc placement** suy từ A.1.4 + Part D §D.2:
- Concept Part B đi vào client/ **phải** thuộc `domain-core` (entity types) hoặc `proto` (contract gRPC/REST) — đây là **OPEN shared contract** mà control-plane depends ngược (D.4).
- Concept vendor-side (Subscription runtime data, TierFeatureSet runtime, vendor governance log) **KHÔNG** xuất hiện trong client repo — chúng thuộc CLOSED control-plane.
- Concept hybrid (`AdminAccessPolicy`, `JitRequest`, `Pattern4Whitelist`…) — *contract type* đi vào `proto` (client API surface); *runtime evaluation* ở control-plane.

**Snapshot 2026-06-11**:
- B.1 ubiquitous language: 8 concept group → `domain-core` (stub) + `proto` (contract stub).
- B.3 11 bounded context: 6 client-touching + 5 NA-client. Verify: NA-client KHÔNG có type/module name tương ứng trong client.
- B.4 8 cross-context protocol: 5 client-touching (Agent-side) + 3 control-plane-only. + Part C `[A]` Org/Workspace protocol (defer).
- B.5 API surface: `proto` skeleton 10 RPC method + Admin API REST contract.
- B.6 storage: namespace template trong `proto`; PostgreSQL/S3 = NA-client.

-----

## H.1 — Quy tắc placement (suy từ principle)

| Quy tắc | Principle ép | Hệ quả |
|---|---|---|
| Concept "agent-side runtime state" → `agent-core` | P.1 + A.3.1 hexagonal | State quản trong agent crate, không leak qua port |
| Concept "shared contract giữa agent ↔ control-plane" → `domain-core`/`proto` | A.1.4 + P.7 | OPEN; control-plane depends ngược (D.4) |
| Concept "crypto primitive / cert chain" → `crypto` | P.1 + intensity Critical | Cite mọi primitive doc; agent verify chain client-side |
| Concept "vendor-managed lifecycle runtime" → **NA-client** | A.1.4 + Part D §D.2 | Vendor-side data, không audit surface → CLOSED |
| Concept "Part C `[A]` deferred" (Organization, Workspace runtime) → **KHÔNG add** | P.8 + Part C §H.7.2 | Anti-pattern: pre-build trước trigger L_subsidiary |

> ⚠️ **Cấm**: thêm concept vendor-side vào `domain-core` "để sẵn cho control-plane import" — phá A.1.4 (client → control-plane là 1 chiều: client cung cấp contract, control-plane consume) + leak operational IP qua public repo.

-----

## H.2 — B.1 Ubiquitous Language → crate

8 concept group per Part B §B.1.1-§B.1.8:

| B.1.x | Concept | Crate đỡ | Status 1.1 |
|---|---|---|---|
| B.1.1 | `Operator`, `ProductLine` | `domain-core` | 🟡 enum stub |
| B.1.1 | `Customer`, `Tenant` | `domain-core` | 🟡 stub (Customer carry `product_line`; Tenant carry `(customer_id, product_line, tenant_id)`) |
| B.1.1 | `Organization`, `Workspace` (A.1.24 defer) | `domain-core` | ✅ **KHÔNG add** — đúng (anti-pattern Part C §H.7.2) |
| B.1.1 | `Node`, `Service`, `User`, `Admin` | `domain-core` + `crypto` (cert chain) | 🟡 stub |
| B.1.2 | `Tag`, `Role`, `IdentityClaim`, `AAL`, `Policy`/`Decision` | `domain-core` + `proto.Intent`/`Decision` | 🟡 stub |
| B.1.3 | `Tunnel`, `Intent`, `OverlayIP`, `Endpoint` | `agent-core` (state) + `proto` (contract) | 🟡 stub |
| B.1.4 | `NodeTier` 1-4, `DataClassification`, `WorkloadKind` (9 variant), `MeshDeploymentPattern` (A/B/C) | `domain-core` (enum) + `agent-core` (apply pattern) | 🟡 stub |
| B.1.5 | `AuditEvent`, `Block`, `LedgerFamily`, `Witness` | `ledger-client` + `proto.ReportEvent`/`StreamLog` | 🟡 skeleton |
| B.1.6 | `ControlPlaneRole`, `Capability`, `TenantConfig`, `AdminAccessPolicy` | `proto` (Admin API contract) | 🟡 skeleton |
| B.1.7 | `Deployment Mode` (vendor-side runtime) | NA-client | ✅ NA |
| B.1.8 | `Commercial Tier`, `Subscription`, `TierFeatureSet`, `Lifecycle Event` | NA-client (vendor-managed) | ✅ NA |
| B.1.8 | `OrgBillingMode`, `OrgInvoiceRollup`, `OrgLifecycleEvent` (A.1.24 Part C) | NA-client + deferred | ✅ NA + deferred |

**Hardware classification (B.1.4)**: enum platform → hardware tier (T1-T2 Layer 1 mandatory: TPM 2.0 / T2 chip / Secure Enclave / StrongBox / Nitro Enclave / Shielded VM / Confidential VM). `domain-core` định nghĩa enum + pre-check tool ở `cli` (`mesh-agent precheck --tier <N> --commercial-tier <F>`).

-----

## H.3 — B.3 Bounded Context → client touchpoint

11 context per Part B §B.3, 6 client-touching + 5 NA-client:

| Context | Trách nhiệm | Client touchpoint | Status 1.1 |
|---|---|---|---|
| B.3.1 Identity & Enrollment | TenantCA chain, enrollment ceremony, hardware attestation, revoke | `crypto` (cert chain verify) + `proto.Enroll(EnrollmentCompletion)` + ceremony rule "đổi domain = enroll mới" | 🟡 skeleton |
| B.3.2 Policy & Authorization | Policy block ledger, compile, evaluate Intent | `proto.FetchPolicy` (agent fetch lazy); `proto.SubmitIntent` carries identity_claim | 🟡 skeleton |
| B.3.3 Connection Broker | Resolve Intent → Decision + ephemeral key | `proto.SubmitIntent`/`RefreshGrant` (agent-side client); capability negotiation theo agent version | 🟡 skeleton |
| B.3.4 Data Plane (Tunneling) | WireGuard mesh, NAT traversal, overlay IP, mesh deployment pattern | `agent-core` (WireGuard wrapper, tunnel state, Path 2 logic); `domain-core.MeshDeploymentPattern` | 🟡 skeleton (core target milestone 1.1) |
| B.3.5 Inspection (WAF/DLP) | Internal WAF sidecar L7, DLP pattern | **NA-client** (sidecar control-side; open-candidate `[A]` chốt khi build milestone 1.2) | ✅ NA |
| B.3.6 Audit & Compliance | NATS → S3 pipeline, redaction at node, witness anchor | `proto.ReportEvent`/`StreamLog`; redaction logic ở `agent-core` (per A.1.2) | 🟡 skeleton |
| B.3.7 Tenant Operations | RBAC control-plane, approval workflow, AdminAccessPolicy, JIT elevation | `proto` Admin API contract types (`AdminAccessPolicy`, `JitRequest`) | 🟡 contract skeleton |
| B.3.8 Customer Lifecycle | Signup, tier transition, billing, offboard | **NA-client** (vendor-managed) | ✅ NA |
| B.3.9 Control Plane Access | Vendor role per-PL, 5-layer defense, ceremony VendorRoot | **NA-client** (control-plane) | ✅ NA |
| B.3.10 Release & Version Lifecycle | Single CI pipeline, dual signing, force-upgrade, capability negotiation | Agent update channel + rollback (`agent-daemon`); Cosign verify | 🟡 skeleton |
| B.3.11 Personal Edge Channel | Edge proxy `*.mesh.dev`, signup gate, abuse defense F0/F0-Plus | **NA-client** (vendor edge) | ✅ NA |

**Verify NA-client**: grep negative — `rg "lifecycle_admin|vendor_role|edge_channel|waf_sidecar"` trong client crates phải = 0 match. Test ở `docs/qc-discipline.md` H.4 pattern.

-----

## H.4 — B.4 Cross-context Protocol

8 protocol per Part B §B.4 + Part C `[A]` Org/Workspace protocol:

| Protocol (B.4.x) | Loại | Client touchpoint | Status 1.1 |
|---|---|---|---|
| B.4.1 Intent Resolution (Agent ↔ Broker) | Agent-side | `proto.SubmitIntent` + cross-PL constraint (cert verify fail ở TLS) | 🟡 skeleton |
| B.4.2 Enrollment (Tier 1 ceremony) | Agent-side | `proto.Enroll`; hardware attestation field; 3-party signature trong block | 🟡 contract skeleton |
| B.4.3 Audit Event Streaming | Agent-side | `proto.ReportEvent`/`StreamLog`; redaction tại node | 🟡 skeleton |
| B.4.4 Policy Block Submission | Admin-side | `proto` Admin API `POST /v1/policies` contract | 🟡 contract skeleton |
| B.4.5 Pattern 4 Whitelist Update | Admin-side | `proto` Admin API + `Pattern4Whitelist` type | 🟡 contract skeleton |
| B.4.6 JIT Admin Elevation | Admin-side | `proto` Admin API + `JitRequest` type | 🟡 contract skeleton |
| B.4.7 Tenant Creation | Vendor-side | **NA-client** (VendorAdmin op) | ✅ NA |
| B.4.8 Vendor Ceremony | Vendor-side | **NA-client** (Operator Root rotation) | ✅ NA |
| **Part C `[A]` Org/Workspace** | Deferred | **KHÔNG đặc tả** ở milestone 1.1 (anti-pattern Part C §H.7.2) | ✅ deferred |

**Cross-PL constraint** (B.4.1): Broker reject Intent nếu source/target khác PL — trust chain không interchangeable (A.1.18). Client embodies: agent connect đúng broker per-PL theo node cert; cert verify fail cross-PL ở TLS layer per Part B §B.5.1.

-----

## H.5 — B.5 API Surface

### B.5.1 Agent API (gRPC/Tonic) — sống ở `proto` crate

10 RPC method per Part B §B.5.1:

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

**Per-PL constraint**: agent connect Broker endpoint per-PL theo node cert (Personal CA chain → Personal Broker; Enterprise CA chain → Enterprise Broker). Cross-PL verify fail ở TLS. Contract test ở `docs/qc-discipline.md` Lớp 4.

### B.5.2 Admin API (REST + WebSocket/Axum) — contract type ở `proto`

Endpoint per tenant, PL inherited. Surface chính:
- `POST/GET /v1/policies` — policy block submission
- `POST /v1/enrollments` + `/{id}/approve` — enrollment workflow
- `GET/DELETE /v1/nodes[/{id}]` — node management
- `POST/GET/PUT/DELETE /v1/admin-policies[/{id}]` — admin access management
- `POST/GET/PUT/DELETE /v1/pattern4-whitelists[/{id}]` — Pattern 4 whitelist
- `POST/GET /v1/jit-requests[/{id}/approve]` — JIT elevation (Enterprise)
- `POST/GET /v1/nodes/{id}/workload` — workload declaration
- `GET/DELETE /v1/admin-sessions[/{id}[/recording]]` — admin session (F3 Enterprise)

**API host per-PL**: `api.personal.mesh.dev` / `api.enterprise.mesh.dev` (hoặc customer-branded F2 Growth+). Admin auth dùng OIDC provider per-PL.

**Part C `[A]` Org-level endpoint** (invoice rollup / org dashboard / Workspace management): KHÔNG đặc tả ở milestone 1.1.

-----

## H.6 — B.6 Storage namespace

### B.6.1 NATS subject namespace (client touchpoint)

Template trong `proto` crate, enforce qua A.1.11:

```
personal.tenant.<tid>.{audit|event|policy|intent}.*
enterprise.tenant.<tid>.{audit|event|policy|intent}.*
```

Agent publish/subscribe đúng PL theo node cert. Cross-PL routing **KHÔNG** tồn tại (separate cluster).

### B.6.2 PostgreSQL + S3

`PostgreSQL` (control-plane RDS) + `S3 layout` (audit/ledger/session-recording bucket per-PL) = **NA-client**. Client touch qua API (`proto.ReportEvent` → control-plane → S3), không direct.

### B.6.3 Part C `[A]` Workspace sub-namespace

Đề xuất `<pl>.tenant.<tid>.ws.<wid>.*` — Part C, KHÔNG đặc tả milestone 1.1.

-----

## H.7 — Việc của owner

1. **Ratify quy tắc placement** (H.1) — đứng tên rằng vendor-side concept KHÔNG đi vào client repo dù "tiện cho control-plane import".
2. **Confirm NA-client verification** — grep negative tests đủ cover (B.3.5 WAF/B.3.8 lifecycle/B.3.9 control plane/B.3.11 Personal edge); xem `docs/qc-discipline.md` H.4.
3. **A.1.24 concept defer = đúng** — đứng tên KHÔNG add `Organization`/`Workspace` runtime type vào `domain-core` cho tới khi L_subsidiary fire.
4. **Update cadence** — refresh file này khi `proto`/`domain-core` add type/contract mới; nếu thêm concept không có ở Part B = phải amend Part B trước (SSOT).

-----
-----

# [R] — Phần kiểm chứng

## R1 — Method

**Verification level**: contract-level (concept type exists trong `domain-core`/`proto` + signature match Part B §B.5). Runtime evaluation (broker decide, policy compile) = control-plane scope, không verify được trong client.

**Cơ chế chuyển 🟡 → ✅**: contract test pass theo pattern `docs/qc-discipline.md` H.2 Lớp 4 + marker `QC-concept[B.x.y]`; NA-client verify bằng grep negative test.

## R2 — T/A markings

- **`[T]`**: 8 concept group B.1; 11 bounded context B.3; 8 protocol B.4; API surface B.5; namespace B.6.3 = full text Part B; quy tắc placement = derive từ A.1.4 + Part D §D.2.
- **`[A]`**: 15 mục 🟡 — contract skeleton, full signature pending; `OrgBillingMode` + `Workspace` runtime construct = Part C deferred.
- **`[A risk-accepted, owned]`**: A.1.24 deferred concept (đúng); B.3.5 WAF open-candidate (chốt milestone 1.2).

## R3 — Log

- **init** (2026-06-11): rà B.1 (8 group) + B.3 (11 context, 6 client-touching + 5 NA) + B.4 (8 protocol + Part C `[A]`) + B.5 (10 RPC + REST surface) + B.6 (NATS namespace + NA-client storage). Snapshot milestone 1.1. Sinh ra từ `INVARIANT-COVERAGE.md` H.4 (xoá) khi refactor sang CP structure.

-----
