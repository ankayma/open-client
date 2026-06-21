# QC Discipline — Test methodology + marker convention (stable)

> **Scope**: cơ chế verify "không conflict Part A/B" + chuyển trạng thái 🟡 → ✅ trong invariant/concept trace; **stable cross-milestone**.
> **Pace layer** `[T per P.5]`: discipline = slow change (5+ năm); file này refresh khi pattern tự nó evolve, không phải mỗi milestone.
> **Quan hệ**:
> - Trạng thái invariant Part A → `docs/invariant-trace.md`
> - Map concept Part B → `docs/concept-trace.md`
> - Mapping table cụ thể (invariant → test, concept → test) + CI gate per milestone → `docs/phase-completion-checklist-<X.Y>.md`
>
> **Cách đọc** (D-00 §4): [H] method + convention; [R] suy dẫn, T/A, log.

-----
-----

# [H] — Dành cho coder/owner

## H.0 — Tóm tắt chốt trước

Test/QC = **cơ chế đóng băng phán xét human review thành check tự động** (P.1 structure absorbs execution). Mỗi check 🟡 → ✅ trong `invariant-trace.md` đòi một test pass theo pattern file này.

**Ba lớp completion** (Part C §H.2):
1. **Phase completion** (4 loại tiêu chí Part C §H.2 rubric L3+) — owner + business, KHÔNG verify bằng test code.
2. **Milestone completion** — eng + owner, verify bằng `phase-completion-checklist-X.Y.md`.
3. **Engineering correctness** (per commit) — Claude session + reviewer, verify bằng `cargo test` + invariant test + contract test mỗi PR.

**"Không conflict Part A/B" = 3 lớp non-violation**:
1. **Part A invariant** — code structure không phá invariant.
2. **Part B concept** — entity/contract khớp ubiquitous language + API signature.
3. **Part C scope gate** — không pre-build feature ngoài milestone.

**Bốn lớp test** (suy theo principle list):

| Lớp | Verify gì | Principle ép | Tool |
|---|---|---|---|
| 1. Compile/platform matrix | 5 platform build clean | P.2 strict admission | `cargo check --target=...` |
| 2. Unit/integration | Domain logic, primitive correctness | P.1 absorb execution lỗi | `cargo test` per crate |
| 3. **Invariant test** | Code không vi phạm A.1.x | P.1 + P.2 structurally enforce | Pattern `invariant_a_*.rs` |
| 4. Contract test | `proto`/`domain-core` match Part B §B.5 | P.5 SSOT discipline | Pattern `contract_b_*.rs` |

> ⚠️ **Test fail = STOP**. Invariant test fail = code đang vi phạm Part A → **amend Part A trước, KHÔNG patch test cho qua** (P.2 cấm shortcut). Contract test fail = drift với Part B → align với SSOT, không "chỉnh test".

-----

## H.1 — Ba lớp completion (đừng nhập nhằng)

| Lớp | Sở hữu | Verify bằng | Tham chiếu |
|---|---|---|---|
| **Phase completion** | Owner + business | Trigger + hypothesis + scoreboard L3+ + honesty | Part C §H.2.2 |
| **Milestone X.Y completion** | Eng + owner | Built list ✅ + completion criteria + CI gate pass | `phase-completion-checklist-X.Y.md` |
| **Engineering correctness** | Eng session | 4 lớp test + structural lint + scope gate | File này + CLAUDE.md §T/A |

Phase completion là *superset* — chứa cả market signal không test được. Eng team chỉ accountable cho 2 lớp dưới.

-----

## H.2 — Bốn lớp test

### Lớp 1 — Compile/platform matrix `[T per P.2]`

Mesh agent target 5 platform (Linux/macOS/Windows/iOS/Android per Part C §H.3.1). Pattern:

```bash
for tgt in x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-pc-windows-msvc \
           aarch64-apple-ios aarch64-linux-android; do
    cargo check --target=$tgt --workspace
done
```

Platform `#[cfg]` code = **Critical intensity** per CLAUDE.md §T/A (cite mọi platform doc).

### Lớp 2 — Unit/integration test `[T per P.1]`

`cargo test --workspace`. Intensity per CLAUDE.md §T/A:
- `crypto`, platform-specific code = **Critical** — test cover mọi primitive edge case, cite RFC/spec.
- Core logic = **Standard** — happy path + meaningful edge case.
- Util/logging = **Light**.
- Generated `proto` binding = **Skip** (test ở Lớp 4 contract).

### Lớp 3 — Invariant test `[T per P.1 + P.2]`

Pattern file bắt buộc:

```rust
// crates/<C>/tests/invariant_a_1_<x>.rs
//! Invariant: A.1.<x> — <tóm tắt 1 dòng>.
//! [T per Part A §A.1.<x>]
//! QC[<milestone>] QC-invariant[A.1.<x>]

#[test]
fn <assertion_name>() {
    // Assert structural property
    // Fail message phải cite invariant ID
}
```

**Quy tắc bất biến**:
- 1 file = 1 invariant; multiple test trong file OK nếu cùng phục vụ 1 invariant.
- Fail message bắt buộc cite invariant ID (vd `"vi phạm A.1.9 — PL phải là deploy dim, không phải crate split"`).
- Test = assertion về *structure* (workspace/type/import/cfg), không phải runtime behavior. Runtime behavior thuộc Lớp 2.
- Sửa test = sửa code, KHÔNG sửa assertion. Muốn relax assertion = amend Part A invariant (Part A thắng).
- Test fail = STOP, escalate human (CLAUDE.md "vi phạm = STOP, báo human").

### Lớp 4 — Contract test `[T per P.5 SSOT]`

Snapshot/golden test cho `proto` + `domain-core` vs Part B. Drift detector — đổi contract một phía mà không cập nhật Part B = test fail. Pattern:

```rust
// crates/<C>/tests/contract_b_<x>_<y>_<surface>.rs
//! Contract: Part B §B.<x>.<y> — <API surface>.
//! [T per Part B §B.<x>.<y>]
//! QC[<milestone>] QC-concept[B.<x>.<y>]

#[test]
fn <surface>_matches_part_b() {
    // Assert proto/struct shape khớp Part B signature
}
```

**Quy tắc bất biến**:
- 1 file = 1 concept/protocol/API surface.
- Fail = SSOT drift. Fix bằng align với Part B; nếu Part B sai = amend Part B trước.
- Negative contract test cho NA-client concept: grep absence (`assert_no_type!("Subscription")`, `assert_no_module!("lifecycle_admin")`).

-----

## H.3 — QC marker convention (grep-able)

Mở rộng CLAUDE.md §T/A bằng marker dành riêng cho test gate:

| Marker | Nghĩa | Grep |
|---|---|---|
| `QC[X.Y]` | Test phải pass trước exit milestone X.Y | `rg 'QC\[1\.1\]'` |
| `QC-invariant[A.1.x]` | Test bind vào invariant Part A cụ thể | `rg 'QC-invariant\[A\.'` |
| `QC-concept[B.x.y]` | Test bind vào concept Part B | `rg 'QC-concept\[B\.'` |
| `QC-scope[Part C §H.x]` | Test enforce scope gate (chống pre-build) | `rg 'QC-scope\['` |
| `QC-defer[A]` | Chấp nhận defer (lý do + verify-plan trong cùng comment) | `rg 'QC-defer\['` |

**Vị trí marker**: trong **module-level doc comment** của file test (đầu file, dạng `//! QC[1.1] QC-invariant[A.1.9]`). Một file = một concern; nhiều marker OK nếu test cover nhiều invariant/concept.

**Đối xứng với CLAUDE.md §T/A**: `[T:source-id]` mark trong code = invariant cite trong test. Cùng discipline, áp lên hai mặt: code commentary và verification.

-----

## H.4 — Test pattern cho 4 nhóm coverage

| Nhóm (`invariant-trace.md` H.1) | Test pattern | Ví dụ |
|---|---|---|
| **STRUCTURAL-in-client** | Lớp 3 invariant test trên workspace/crate/type structure | `assert!(!crates.contains_personal_or_enterprise())` cho A.1.9 |
| **CONTRACT-enables** | Lớp 4 contract test trên `proto`/`domain-core` shape | `assert_eq!(parse_proto_methods("AgentControl"), [...])` cho B.5.1 |
| **DEFERRED-to-deployment** | Lớp 4 contract + Lớp 1 cross-platform compile | `proto` template `<pl>.tenant.<id>.>` accept 2 PL prefix |
| **NA-for-client** | Lớp 3 negative test — grep absence | `assert_no_module!(["lifecycle_admin", "vendor_role"])` |

**Scope gate test** (anti-pre-build per Part C §H.7.2) = Lớp 3 negative test với marker `QC-scope`:

```rust
// tests/scope_gate_<milestone>_<concern>.rs
//! QC[<milestone>] QC-scope[Part C §H.7.2]: <anti-pattern>.
#[test]
fn no_<deferred_type>_yet() {
    assert_no_type!("<TypeName>");
}
```

Khi trigger fire (vd L_subsidiary) → archive scope gate test cũ + add type → test "có type" thay vào (loop closure).

-----

## H.5 — STOP semantics

| Tình huống | Hành động | Lý do |
|---|---|---|
| Invariant test (Lớp 3) fail | STOP. Code vi phạm Part A → amend Part A trước. KHÔNG patch test. | P.2 cấm shortcut; Part A thắng (CLAUDE.md) |
| Contract test (Lớp 4) fail | Align với Part B SSOT. Nếu Part B sai = amend Part B trước. | P.5 SSOT discipline |
| Scope gate test fail | STOP. Đang pre-build feature ngoài milestone → xoá feature. KHÔNG xoá test. | P.8 + Part C §H.7.2 |
| Lớp 1/2 (compile/unit) fail | Fix code bình thường (engineering bug) | Routine |
| Platform-specific test fail trên 1 platform | STOP per platform; Critical intensity → cite platform doc + reproduce | A.1.20 capability negotiation phải đảm bảo cross-platform |

**Honest reporting**: trước khi báo "done" cho human, chạy đủ `cargo fmt --check` + `cargo clippy -- -D warnings` + `cargo check` + `cargo test`; report kết quả trung thực — test fail thì nói fail kèm output, đừng tô hồng (CLAUDE.md §Workflow + P.3).

-----

## H.6 — Việc của owner

1. **Ratify 4 lớp test framework** + QC marker convention. Owner đứng tên rằng đây là cách verify đúng cho repo OPEN của vendor 2-PL.
2. **STOP semantics confirm** — invariant test fail = amend Part A, không patch test. (CLAUDE.md đã ghi; file này ratify cụ thể.)
3. **Marker grep-coverage threshold** — đề xuất:
   - Mỗi A.1.x ở STRUCTURAL-in-client (`invariant-trace.md`) có ≥1 `QC-invariant` test khi crate có code thực.
   - Mỗi context Part B.3.x có "Client touchpoint" non-NA (`concept-trace.md`) có ≥1 `QC-concept` test khi `proto`/`domain-core` có type.
   - Scope gate test bao phủ đủ anti-pattern Part C §H.7.2 *hiện hành milestone*.
4. **Pattern evolution** — file này refresh khi pattern tự nó evolve (vd thêm 1 lớp test mới, vd property-based testing). Hiếm; mỗi lần evolve = log + ratify owner.

-----
-----

# [R] — Phần kiểm chứng

## R1 — Suy dẫn về principle list

| Test mechanism | Principle ép | Hệ quả |
|---|---|---|
| 4 lớp test (compile/unit/invariant/contract) | P.1 (kiến trúc hấp thụ execution) | Test = đóng băng phán xét vào structure; vi phạm caught compile time |
| Invariant test fail = STOP, amend Part A trước | P.2 (strict admission) | Cấm shortcut "patch test cho qua" |
| `// TODO[A]:` + lý do trong test gap + `QC-defer[A]` | P.3 (honest gap) | Gap surface ở mức code, không giấu |
| Snapshot/golden test contract vs Part B | P.5 (three layers) | Code = implementation; contract test = bridge với Part B SSOT |
| 5 platform compile matrix | P.6 (single codebase 2 PL) + A.1.9 | Forced verify: code single chạy đúng cross-platform = bài test thực của A.1.9 |
| QC marker grep-able + coverage metric | P.3 + P.5 | Honest gap đo được; SSOT discipline (test trỏ Part A/B section) |
| Scope gate test = anti-pre-build | P.8 (trigger-based activation) | "Pre-build = anti-pattern" trở thành test fail-fast; trigger fire = test rotation |
| QC-invariant cite Part A section | P.5 SSOT discipline | Test trace tới invariant; không có invariant ID = không nên có test (tránh test-vì-test) |
| Pace layer: discipline file (this) stable; mapping file per-milestone | P.5 three layers | Discipline đổi chậm; mapping theo phase đổi 6-18mo |

## R2 — T/A markings

- **`[T]`**: 3 lớp completion model = Part C §H.2 + Part D §D.1; 4 lớp test = derive từ P.1/P.2/P.3/P.5; QC marker convention = mở rộng CLAUDE.md §T/A; STOP semantics = CLAUDE.md "vi phạm = STOP".
- **`[A]`**: Coverage threshold (≥1 test per invariant STRUCTURAL) — đề xuất, owner ratify; pattern evolution timing — refresh hiếm.
- **`[A risk-accepted, owned]`**: T/A linter defer milestone 1.1 CI (CLAUDE.md `[A]`); chấp nhận convention thủ công + human review trong milestone 1.1 trước khi CI enforce.

## R3 — Log

- **init** (2026-06-11): 3 lớp completion + 4 lớp test + QC marker convention + STOP semantics. Stable cross-milestone framework. Sinh ra từ `docs/QC-GATES.md` (xoá) khi refactor sang CP structure; phần milestone-specific mapping table + CI gate đẩy sang `phase-completion-checklist-X.Y.md`.

-----
