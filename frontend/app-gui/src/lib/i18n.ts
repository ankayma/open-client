export type Lang = 'vn' | 'en';

export const STRINGS: Record<Lang, Record<string, string>> = {
  vn: {
    // navigation
    nav_services:  'Dịch vụ',
    nav_admin:     'Quản trị',
    nav_settings:  'Cài đặt',
    nav_users:     'Người dùng',
    nav_devices:   'Thiết bị của tôi',
    nav_account:   'Tài khoản',
    nav_security:  'Bảo mật',

    // common buttons
    btn_edit:       'Sửa',
    btn_revoke:     'Thu hồi',
    btn_enroll:     'Kết nạp',
    btn_invite:     'Mời',
    btn_save:       'Lưu',
    btn_cancel:     'Hủy',
    btn_delete:     'Xóa',
    btn_export:     'Xuất',
    btn_ssh:        'SSH ↗',
    btn_connect:    'Kết nối',
    btn_disconnect: 'Ngắt kết nối',
    btn_review:     'Xem →',
    btn_register:   'Đăng ký',
    btn_send:       'Gửi',
    btn_filter:     'Lọc',
    btn_new:        'Thêm mới',
    btn_add:        'Thêm',

    // status
    status_online:  'Đang kết nối',
    status_offline: 'Mất kết nối',
    status_pending: 'Chờ duyệt',
    status_active:  'Đang hoạt động',

    // page titles
    title_services: 'Dịch vụ',
    title_users:    'Người dùng & Vai trò',
    title_settings: 'Cài đặt',
    title_invite:   'Mời người dùng',

    // pre-flight permission gate (shown once after sign-in, before first Connect)
    pf_intro:         'Sắp xong',
    pf_helper_title:  'Còn một bước thiết lập',
    pf_helper_body:   'Ankayma cần một tiến trình nền để chạy đường hầm bảo mật. Bật “Ankayma” trong System Settings → General → Login Items & Extensions → App Background Activity là xong.',
    pf_vpn_title:     'Còn một bước thiết lập',
    pf_vpn_body:      'Ankayma cần quyền thêm cấu hình VPN cho đường hầm bảo mật. Chọn “Cho phép” khi thiết bị hỏi.',
    pf_action_helper: 'Mở System Settings',
    pf_action_vpn:    'Cho phép VPN',
    pf_waiting:       'Đang chờ bạn phê duyệt…',
    pf_ready:         'Xong — có thể kết nối',
  },

  en: {
    // navigation
    nav_services:  'Services',
    nav_admin:     'Admin',
    nav_settings:  'Settings',
    nav_users:     'Users',
    nav_devices:   'My Devices',
    nav_account:   'Account',
    nav_security:  'Security',

    // common buttons
    btn_edit:       'Edit',
    btn_revoke:     'Revoke',
    btn_enroll:     'Enroll',
    btn_invite:     'Invite',
    btn_save:       'Save',
    btn_cancel:     'Cancel',
    btn_delete:     'Delete',
    btn_export:     'Export',
    btn_ssh:        'SSH ↗',
    btn_connect:    'Connect',
    btn_disconnect: 'Disconnect',
    btn_review:     'Review →',
    btn_register:   'Register',
    btn_send:       'Send',
    btn_filter:     'Filter',
    btn_new:        'New',
    btn_add:        'Add',

    // status
    status_online:  'Connected',
    status_offline: 'Offline',
    status_pending: 'Pending',
    status_active:  'Active',

    // page titles
    title_services: 'Services',
    title_users:    'Users & Roles',
    title_settings: 'Settings',
    title_invite:   'Invite User',

    // pre-flight permission gate (shown once after sign-in, before first Connect)
    pf_intro:         'Almost there',
    pf_helper_title:  'One quick setup step',
    pf_helper_body:   'Ankayma needs a background helper to run your secure tunnel. Turn on “Ankayma” under System Settings → General → Login Items & Extensions → App Background Activity, and you’re set.',
    pf_vpn_title:     'One quick setup step',
    pf_vpn_body:      'Ankayma needs permission to add a VPN configuration for your secure tunnel. Tap “Allow” when your device asks.',
    pf_action_helper: 'Open System Settings',
    pf_action_vpn:    'Allow VPN access',
    pf_waiting:       'Waiting for your approval…',
    pf_ready:         'All set — you can connect now',
  },
};

// Action → Lucide icon name mapping (SSOT for icon convention)
export const ACTION_ICONS: Record<string, string> = {
  edit:       'pencil',
  revoke:     'shield-x',
  enroll:     'plus',
  invite:     'user-plus',
  save:       'save',
  cancel:     'x',
  delete:     'trash',
  export:     'download',
  ssh:        'terminal',
  connect:    'wifi',
  disconnect: 'wifi-off',
  review:     'arrow-right',
  register:   'key',
  send:       'send',
  filter:     'list',
  new:        'plus',
  add:        'plus',
  settings:   'settings',
  logout:     'log-out',
  theme:      'moon',
  language:   'globe',
};
