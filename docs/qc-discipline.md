# QC Discipline — Test methodology + marker convention (stable)

> **Scope**: mechanism to verify "no conflict with Part A/B" + state transition 🟡 → ✅ in invariant/concept trace; **stable cross-milestone**.
> **Pace layer** `[T per P.5]`: discipline = slow change (5+ years); this file refreshes when the pattern itself evolves, not on every milestone.
> **Relations**:
> - Part A invariant status → `docs/invariant-trace.md`
> - Part B concept map → `docs/concept-trace.md`
> - Specific mapping table (invariant → test, concept → test) + CI gate per milestone → `docs/phase-completion-checklist-<X.Y>.md`
>
> **How to read** (D-00 §4): [H] method + convention; [R] derivation, T/A, log.

-----
-----

# [H] — For coder/owner

## H.0 — Summary up front

Test/QC = **the mechanism that freezes human review judgment into automated checks** (P.1 structure absorbs execution). Every 🟡 → ✅ transition in `invariant-trace.md` requires a test to pass according to the pattern in this file.

**Three completion layers** (Part C §H.2):
1. **Phase completion** (4 criterion types Part C §H.2 rubric L3+) — owner + business, NOT verified by test code.
2. **Milestone completion** — eng + owner, verified via `phase-completion-checklist-X.Y.md`.
3. **Engineering correctness** (per commit) — Claude session + reviewer, verified via `cargo test` + invariant test + contract test per PR.

**"No conflict with Part A/B" = 3 non-violation layers**:
1. **Part A invariant** — code structure does not break the invariant.
2. **Part B concept** — entity/contract matches ubiquitous language + API signature.
3. **Part C scope gate** — no pre-building features outside the milestone.

**Four test layers** (derived from principle list):

| Layer | What it verifies | Enforcing principle | Tool |
|---|---|---|---|
| 1. Compile/platform matrix | 5 platform build clean | P.2 strict admission | `cargo check --target=...` |
| 2. Unit/integration | Domain logic, primitive correctness | P.1 absorb execution errors | `cargo test` per crate |
| 3. **Invariant test** | Code does not violate A.1.x | P.1 + P.2 structurally enforce | Pattern `invariant_a_*.rs` |
| 4. Contract test | `proto`/`domain-core` match Part B §B.5 | P.5 SSOT discipline | Pattern `contract_b_*.rs` |

> ⚠️ **Test fail = STOP**. Invariant test fail = code is violating Part A → **amend Part A first, DO NOT patch the test to pass** (P.2 forbids shortcuts). Contract test fail = drift with Part B → align with SSOT, do not "adjust the test".

-----

## H.1 — Three completion layers (do not conflate)

| Layer | Owned by | Verified via | Reference |
|---|---|---|---|
| **Phase completion** | Owner + business | Trigger + hypothesis + scoreboard L3+ + honesty | Part C §H.2.2 |
| **Milestone X.Y completion** | Eng + owner | Built list ✅ + completion criteria + CI gate pass | `phase-completion-checklist-X.Y.md` |
| **Engineering correctness** | Eng session | 4 test layers + structural lint + scope gate | This file + CLAUDE.md §T/A |

Phase completion is a *superset* — it includes market signals that cannot be tested. The eng team is only accountable for the 2 lower layers.

-----

## H.2 — Four test layers

### Layer 1 — Compile/platform matrix `[T per P.2]`

Mesh agent targets 5 platforms (Linux/macOS/Windows/iOS/Android per Part C §H.3.1). Pattern:

```bash
for tgt in x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-pc-windows-msvc \
           aarch64-apple-ios aarch64-linux-android; do
    cargo check --target=$tgt --workspace
done
```

Platform `#[cfg]` code = **Critical intensity** per CLAUDE.md §T/A (cite all platform docs).

### Layer 2 — Unit/integration test `[T per P.1]`

`cargo test --workspace`. Intensity per CLAUDE.md §T/A:
- `crypto`, platform-specific code = **Critical** — tests cover all primitive edge cases, cite RFC/spec.
- Core logic = **Standard** — happy path + meaningful edge case.
- Util/logging = **Light**.
- Generated `proto` binding = **Skip** (tested in Layer 4 contract).

### Layer 3 — Invariant test `[T per P.1 + P.2]`

Required file pattern:

```rust
// crates/<C>/tests/invariant_a_1_<x>.rs
//! Invariant: A.1.<x> — <one-line summary>.
//! [T per Part A §A.1.<x>]
//! QC[<milestone>] QC-invariant[A.1.<x>]

#[test]
fn <assertion_name>() {
    // Assert structural property
    // Fail message must cite the invariant ID
}
```

**Invariant rules**:
- 1 file = 1 invariant; multiple tests in the file OK if they all serve the same invariant.
- Fail message must cite the invariant ID (e.g. `"violates A.1.9 — PL must be deploy dimension, not a crate split"`).
- Test = assertion about *structure* (workspace/type/import/cfg), not runtime behavior. Runtime behavior belongs to Layer 2.
- Fixing a test = fixing code, NOT changing the assertion. To relax an assertion = amend the Part A invariant (Part A wins).
- Test fail = STOP, escalate to human (CLAUDE.md "violation = STOP, notify human").

### Layer 4 — Contract test `[T per P.5 SSOT]`

Snapshot/golden test for `proto` + `domain-core` vs Part B. Drift detector — changing the contract on one side without updating Part B = test fail. Pattern:

```rust
// crates/<C>/tests/contract_b_<x>_<y>_<surface>.rs
//! Contract: Part B §B.<x>.<y> — <API surface>.
//! [T per Part B §B.<x>.<y>]
//! QC[<milestone>] QC-concept[B.<x>.<y>]

#[test]
fn <surface>_matches_part_b() {
    // Assert proto/struct shape matches Part B signature
}
```

**Invariant rules**:
- 1 file = 1 concept/protocol/API surface.
- Fail = SSOT drift. Fix by aligning with Part B; if Part B is wrong = amend Part B first.
- Negative contract test for NA-client concept: grep absence (`assert_no_type!("Subscription")`, `assert_no_module!("lifecycle_admin")`).

-----

## H.3 — QC marker convention (grep-able)

Extends CLAUDE.md §T/A with markers dedicated to test gates:

| Marker | Meaning | Grep |
|---|---|---|
| `QC[X.Y]` | Test must pass before exiting milestone X.Y | `rg 'QC\[1\.1\]'` |
| `QC-invariant[A.1.x]` | Test binds to a specific Part A invariant | `rg 'QC-invariant\[A\.'` |
| `QC-concept[B.x.y]` | Test binds to a Part B concept | `rg 'QC-concept\[B\.'` |
| `QC-scope[Part C §H.x]` | Test enforces scope gate (prevents pre-build) | `rg 'QC-scope\['` |
| `QC-defer[A]` | Accepted defer (reason + verify-plan in the same comment) | `rg 'QC-defer\['` |

**Marker location**: in the **module-level doc comment** of the test file (at the top of the file, in the form `//! QC[1.1] QC-invariant[A.1.9]`). One file = one concern; multiple markers OK if the test covers multiple invariants/concepts.

**Symmetry with CLAUDE.md §T/A**: `[T:source-id]` mark in code = invariant cite in test. Same discipline applied to both sides: code commentary and verification.

-----

## H.4 — Test patterns for the 4 coverage groups

| Group (`invariant-trace.md` H.1) | Test pattern | Example |
|---|---|---|
| **STRUCTURAL-in-client** | Layer 3 invariant test on workspace/crate/type structure | `assert!(!crates.contains_personal_or_enterprise())` for A.1.9 |
| **CONTRACT-enables** | Layer 4 contract test on `proto`/`domain-core` shape | `assert_eq!(parse_proto_methods("AgentControl"), [...])` for B.5.1 |
| **DEFERRED-to-deployment** | Layer 4 contract + Layer 1 cross-platform compile | `proto` template `<pl>.tenant.<id>.>` accept 2 PL prefix |
| **NA-for-client** | Layer 3 negative test — grep absence | `assert_no_module!(["lifecycle_admin", "vendor_role"])` |

**Scope gate test** (anti-pre-build per Part C §H.7.2) = Layer 3 negative test with marker `QC-scope`:

```rust
// tests/scope_gate_<milestone>_<concern>.rs
//! QC[<milestone>] QC-scope[Part C §H.7.2]: <anti-pattern>.
#[test]
fn no_<deferred_type>_yet() {
    assert_no_type!("<TypeName>");
}
```

When a trigger fires (e.g. L_subsidiary) → archive the old scope gate test + add type → test "type exists" replaces it (loop closure).

-----

## H.5 — STOP semantics

| Situation | Action | Reason |
|---|---|---|
| Invariant test (Layer 3) fail | STOP. Code violates Part A → amend Part A first. DO NOT patch test. | P.2 forbids shortcuts; Part A wins (CLAUDE.md) |
| Contract test (Layer 4) fail | Align with Part B SSOT. If Part B is wrong = amend Part B first. | P.5 SSOT discipline |
| Scope gate test fail | STOP. Pre-building a feature outside the milestone → delete the feature. DO NOT delete the test. | P.8 + Part C §H.7.2 |
| Layer 1/2 (compile/unit) fail | Fix code normally (engineering bug) | Routine |
| Platform-specific test fail on 1 platform | STOP per platform; Critical intensity → cite platform doc + reproduce | A.1.20 capability negotiation must guarantee cross-platform |

**Honest reporting**: before reporting "done" to human, run `cargo fmt --check` + `cargo clippy -- -D warnings` + `cargo check` + `cargo test`; report results honestly — if tests fail say they failed and include output, do not sugarcoat (CLAUDE.md §Workflow + P.3).

-----

## H.6 — Owner responsibilities

1. **Ratify the 4-layer test framework** + QC marker convention. Owner signs off that this is the correct verification method for the 2-PL vendor OPEN repo.
2. **Confirm STOP semantics** — invariant test fail = amend Part A, do not patch test. (CLAUDE.md already states this; this file ratifies it specifically.)
3. **Marker grep-coverage threshold** — proposed:
   - Each A.1.x in STRUCTURAL-in-client (`invariant-trace.md`) has ≥1 `QC-invariant` test when the crate has real code.
   - Each Part B.3.x context with a non-NA "Client touchpoint" (`concept-trace.md`) has ≥1 `QC-concept` test when `proto`/`domain-core` has a type.
   - Scope gate tests cover all anti-patterns from Part C §H.7.2 *for the current milestone*.
4. **Pattern evolution** — this file refreshes when the pattern itself evolves (e.g. adding a new test layer, e.g. property-based testing). Rare; each evolution = log + owner ratification.

-----
-----

# [R] — Verification section

## R1 — Derivation from principle list

| Test mechanism | Enforcing principle | Consequence |
|---|---|---|
| 4 test layers (compile/unit/invariant/contract) | P.1 (architecture absorbs execution) | Test = freezes judgment into structure; violations caught at compile time |
| Invariant test fail = STOP, amend Part A first | P.2 (strict admission) | Forbids the shortcut "patch test to pass" |
| `// TODO[A]:` + reason in test gap + `QC-defer[A]` | P.3 (honest gap) | Gap surfaced at code level, not hidden |
| Snapshot/golden test contract vs Part B | P.5 (three layers) | Code = implementation; contract test = bridge to Part B SSOT |
| 5 platform compile matrix | P.6 (single codebase 2 PL) + A.1.9 | Forced verify: single codebase runs correctly cross-platform = the real test of A.1.9 |
| QC marker grep-able + coverage metric | P.3 + P.5 | Honest gap is measurable; SSOT discipline (test points to Part A/B section) |
| Scope gate test = anti-pre-build | P.8 (trigger-based activation) | "Pre-build = anti-pattern" becomes a fail-fast test; trigger fire = test rotation |
| QC-invariant cite Part A section | P.5 SSOT discipline | Test traces to invariant; no invariant ID = should not have a test (avoids testing for testing's sake) |
| Pace layer: discipline file (this) stable; mapping file per-milestone | P.5 three layers | Discipline changes slowly; phase mapping changes every 6-18mo |

## R2 — T/A markings

- **`[T]`**: 3-layer completion model = Part C §H.2 + Part D §D.1; 4 test layers = derived from P.1/P.2/P.3/P.5; QC marker convention = extends CLAUDE.md §T/A; STOP semantics = CLAUDE.md "violation = STOP".
- **`[A]`**: Coverage threshold (≥1 test per invariant STRUCTURAL) — proposed, owner to ratify; pattern evolution timing — refresh rarely.
- **`[A risk-accepted, owned]`**: T/A linter deferred to milestone 1.1 CI (CLAUDE.md `[A]`); manual convention + human review accepted in milestone 1.1 before CI enforces.

## R3 — Log

- **init** (2026-06-11): 3-layer completion + 4 test layers + QC marker convention + STOP semantics. Stable cross-milestone framework. Born from `docs/QC-GATES.md` (deleted) during refactor to CP structure; milestone-specific mapping table + CI gate sections moved to `phase-completion-checklist-X.Y.md`.

-----
