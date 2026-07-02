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
- [ ] **English-only**: diff không còn tiếng Việt trong code/comment/doc/string — dịch trước push; commit latest English (subject + nội dung). Quét: `git diff --cached | grep -nPi '[àáảãạ...ỵ]'` (xem §Public-repo hygiene). Commit cũ VN chấp nhận.
- [ ] **Publish**: khi lên GitHub public → **curated snapshot**, KHÔNG mirror history GitLab thô (§Public-repo hygiene).
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

## Public-repo hygiene (non-negotiable — repo destined GitHub public)

> Authoritative ở đây (file tracked/shared). `CLAUDE.md` bị gitignore = local-only, không dựa vào để share rule.

**Rule 1 — Publish = curated snapshot, KHÔNG mirror history nội bộ.**
Lên GitHub public bằng **snapshot đã squash/lọc** (một "initial public commit" hoặc history đã curate) — **KHÔNG** push thẳng history GitLab nội bộ. Lý do: git history vĩnh viễn; mirror thô lộ WIP, tham chiếu control-plane nội bộ, và mọi secret/pubkey-thật từng lọt commit cũ. Chặn **cấu trúc**, không phải "hy vọng đã xoá". GitLab = SSOT dev nội bộ; GitHub = bản publish sạch. (Secret credential → còn phải rotate; pubkey/non-secret → snapshot sạch là đủ.)

**Rule 2 — English-only *shipped content*; latest commit phải English.**
Code, code-comment, `docs/` user-facing, string literal, README/ARCHITECTURE = **English**. Còn tiếng Việt → **dịch TRƯỚC khi push**. Commit CŨ còn VN: chấp nhận (không rewrite history); commit **MỚI NHẤT phải English** (subject + nội dung file đụng tới). Quét trước push:
```
git diff --cached | grep -nP -i '[àáảãạăắằẳẵặâấầẩẫậđèéẻẽẹêếềểễệìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵ]'
```
Hit trong shipped content → dịch rồi push. **Ngoại lệ**: dev-process meta (`CLAUDE.md`, `CONTRIBUTING.md`) = team-language VN, do Rule 1 lọc/dịch lúc publish — không bị Rule 2 gác per-commit.

Cùng lớp rule áp cho mọi repo public-destined (vd `relay`).

## QC test (human kiểm)

Human sẽ kiểm: build trên máy sạch, test pass, hành vi khớp ý định, không leak closed/secret, diff dễ đọc. Claude viết code + test sao cho các điểm này verify được nhanh.
