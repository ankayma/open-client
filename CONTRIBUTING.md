# Contributing — client/ (OPEN)

Mô hình làm việc: **Claude code 100%, human review + QC test.** Tài liệu này định nghĩa "done" và ranh giới quyết định.

## Vòng lặp

1. **Claude**: đọc constraint (`ARCHITECTURE.md` → blueprint Part A/C/D section liên quan) → code → self-check → commit nhỏ.
2. **Human**: review diff + chạy QC test → approve hoặc trả lại.

## Definition of Done (Claude tự verify trước khi giao)

- [ ] `cargo fmt --check` sạch
- [ ] `cargo clippy -- -D warnings` không warning
- [ ] `cargo check` + `cargo test` pass — **report output thật**, fail thì nói fail
- [ ] Behavior change có test đi kèm
- [ ] Không vi phạm binding invariant (ARCHITECTURE §index); nếu buộc phải → **không commit**, surface cho human
- [ ] Trong scope milestone Part C hiện tại (không pre-build — P.8)
- [ ] **Không có IP closed / secret / khóa thật / customer data** trong diff (repo PUBLIC)
- [ ] Honest gap (`// TODO[A]:` + lý do) cho mọi chỗ chưa hoàn chỉnh — không giấu (P.3)
- [ ] Quyết định mark `[T:source-id]` (vd `[T:A.1.4]`, `[T:RFC-7855§5.4]`) hoặc `[A]`+verify-plan; **bare `[T]` không source = fail** (t-a-coding-core §3.2). Không số "gut" (P.9)
- [ ] Intensity đúng (t-a-coding-core §7, p2p §3/§6): crypto (`crypto`/`agent-core`) + platform `#[cfg]` = **Critical** (cite mọi primitive/platform doc); core logic = Standard; generated `proto` = Skip

## Cần human quyết — Claude KHÔNG tự làm

- Chọn license (Part D §D.7).
- Bất cứ thay đổi nào mâu thuẫn / cần amend Part A invariant (Part A wins — phải sửa Part A trước).
- Build feature ngoài scope milestone hiện tại.
- Thêm dependency mới đáng kể (A.1.21 supply-chain) hoặc đổi contract `proto`/`domain-core` (ảnh hưởng control-plane).

## Commit / branch

- Branch từ `main`; không commit thẳng lên `main` khi chưa review (trừ khi human bảo).
- Commit subject English, imperative, một concern/commit.

## QC test (human kiểm)

Human sẽ kiểm: build trên máy sạch, test pass, hành vi khớp ý định, không leak closed/secret, diff dễ đọc. Claude viết code + test sao cho các điểm này verify được nhanh.
