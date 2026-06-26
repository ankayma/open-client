# UI Work — Design v1.0

Danh sách công việc cần hoàn thành để client đạt design v1.0.  
Mỗi item có thể implement độc lập. Thứ tự trong cùng nhóm = thứ tự ưu tiên.

---

## Brand Assets

**A-1** ✓ `gui/src-tauri/icons/` — icons đã được thay bằng brand chính thức.  
Source gốc: `gui/src-tauri/icons/icon_source.png` (750×750, teal gradient "An" monogram).

**A-2** ✓ Welcome screen — dùng `static/ankayma_icon.png` (750×750, 666 KB).  
Logo lockup (2.2 MB) không dùng trong app — đã xóa khỏi `static/`.

> `favicon.svg` trong `static/` — pure vector, giữ nguyên.  
> `ankayma_app_icon_with_label.png` — dành cho App Store listing, không dùng trong app.

---

## Design System

**DS-1** `src/lib/theme.ts` — thêm mới  
14 themes, `applyTheme(id)`, `THEME_PAIRS` (dark↔light pairs), `SEC_DARK`/`SEC_LIGHT` fixed token sets.  
`applyTheme(id)` ghi `THEMES[id].vars` vào `document.documentElement` (CSS vars trên `:root`).

**DS-2** `src/lib/i18n.ts` — thêm mới  
VN/EN string catalog (`STRINGS`), `ACTION_ICONS` record (action → lucide icon mapping).  
Usage pattern trong routes: `import { activeLang } from '$lib/stores'; import { STRINGS } from '$lib/i18n';` → dùng `STRINGS[$activeLang]['key']` trực tiếp trong template. Không dùng wrapper function.

**DS-3** `src/lib/stores.ts` — bổ sung  
Thêm `activeTheme` và `activeLang` với persistence qua `localStorage`:
```ts
const storedTheme = (typeof localStorage !== 'undefined' && localStorage.getItem('ankayma_theme')) || 'tokyo-night';
const storedLang  = (typeof localStorage !== 'undefined' && localStorage.getItem('ankayma_lang'))  || 'vn';
export const activeTheme = writable<ThemeId>(storedTheme as ThemeId);
export const activeLang  = writable<Lang>(storedLang as Lang);
```
Trong `+layout.svelte` `onMount`: subscribe cả hai store — mỗi khi thay đổi gọi `applyTheme()` và ghi lại `localStorage`. Không xóa `auth`, `connection`, `quota`.

**DS-4** `src/routes/+layout.svelte` — CSS bổ sung  
Thêm vào `:global(:root)`:
- `--sec-allow`, `--sec-deny`, `--sec-info` (fixed layer, không override theo theme)
- `--btn-secondary-bg/border/text`, `--btn-danger-bg/border/text`, `--btn-warn-bg/border/text` (component tokens)

**DS-5** `src/routes/+layout.svelte` — button classes  
Thêm global: `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-warn`, `.btn-ghost`.  
Dùng component tokens từ DS-4. Các route hiện tại đang dùng inline `<button>` style riêng — sau khi có classes này sẽ migrate dần.

---

## Layout / Sidebar

**L-1** User chip — thêm vào cuối sidebar  
Avatar hình tròn với initials từ email. Màu nền phân biệt theo `tier`.  
Hiển thị email + tier label (`F0`, `F0+`, `F1 Starter`).

**L-2** Admin sub-nav — thêm vào sidebar khi signed in  
Các mục: Devices · Members.

**L-3** Theme toggle + Language toggle — thêm vào sidebar  
Hai nút nhỏ (`.pref-btn`) bên cạnh user chip.  
Theme toggle: icon sun/moon — bấm chuyển giữa đúng 2 theme trong pair (`THEME_PAIRS`), không phải picker 14 themes. Ví dụ: `tokyo-night ↔ nord-light`. Gọi `activeTheme.set(THEME_PAIRS[current])`.  
Lang toggle: hiển thị `VN` / `EN` — bấm flip giữa 2 giá trị, gọi `activeLang.set(...)`.  
Cả hai thay đổi tự persist qua subscribe đã setup ở DS-3.

---

## Components

**C-1** `src/lib/components/PathChain.svelte` — thêm mới  
Modal hiển thị proof-of-path: danh sách peers trên data path, mỗi peer có hostname, overlay IP, trạng thái direct/relay, endpoint. Badge màu theo `--sec-*` tokens.  
Dùng type `PathProof` + `PathPeer` đã có trong `src/lib/types.ts`.

---

## Routes

> Với mỗi route: giữ nguyên `<style>` block hiện có, chỉ đổi data binding sang Tauri IPC. Không rewrite CSS.

**R-2** `/settings` — áp design đầy đủ  
Thiếu: layout 3 section (Account · Security · Network), node info display, public key display.  
Data source: `getNodeInfo()` — đã có trong `tauri.ts`.

**R-3** `/devices` — áp design layout  
Thiếu: node status badges dùng `--sec-*` tokens, action buttons dùng `.btn-danger`/`.btn-secondary` (DS-5).  
Data source: `listNodes()`, `deleteNode()`, `getNodeInfo()` — đã có trong `tauri.ts`.

**R-4** `/members` — CSS polish  
Current page đã feature-complete: `listMembers()`, `inviteMember()`, `joinTeam()`, `removeMember()` — tất cả có backend và UI.  
Chỉ thiếu: `.btn-danger` class cho remove button (chờ DS-5), role badge styling.  
Không cần thay đổi logic hay data fetching.
