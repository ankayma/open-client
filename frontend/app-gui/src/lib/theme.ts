export type ThemeId =
  | 'primer-dark' | 'apple-dark' | 'fluent-dark' | 'material-dark'
  | 'primer-light' | 'apple-light' | 'fluent-light' | 'material-light'
  | 'tokyo-night' | 'nord' | 'catppuccin-mocha'
  | 'nord-light' | 'catppuccin-latte' | 'solarized';

export interface Theme {
  id: ThemeId;
  label: string;
  description: string;
  dark: boolean;
  group: 'reference' | 'community';
  preview: { bg: string; surface: string; accent: string; danger: string };
  vars: Record<string, string>;
}

// Security state layer — fixed, never overridden by brand theme
export const SEC_LIGHT: Record<string, string> = {
  '--sec-allow': '#1A7F37',
  '--sec-deny':  '#CF222E',
  '--sec-info':  '#0969DA',
};
export const SEC_DARK: Record<string, string> = {
  '--sec-allow': '#3FB950',
  '--sec-deny':  '#FF6B6B',
  '--sec-info':  '#4493F8',
};

// Smart toggle pairs — sidebar moon/sun switches to the matching variant
export const THEME_PAIRS: Partial<Record<ThemeId, ThemeId>> = {
  'primer-dark':      'primer-light',    'primer-light':      'primer-dark',
  'apple-dark':       'apple-light',     'apple-light':       'apple-dark',
  'fluent-dark':      'fluent-light',    'fluent-light':      'fluent-dark',
  'material-dark':    'material-light',  'material-light':    'material-dark',
  'nord':             'nord-light',      'nord-light':        'nord',
  'catppuccin-mocha': 'catppuccin-latte','catppuccin-latte':  'catppuccin-mocha',
};

const btnTokens = {
  tinted: {
    '--btn-secondary-bg':     'var(--c-surface)',
    '--btn-secondary-border': 'var(--c-border)',
    '--btn-secondary-text':   'var(--c-text)',
    '--btn-danger-bg':        'color-mix(in srgb, var(--c-danger) 16%, var(--c-surface))',
    '--btn-danger-border':    'color-mix(in srgb, var(--c-danger) 45%, transparent)',
    '--btn-danger-text':      'var(--c-danger)',
    '--btn-warn-bg':          'color-mix(in srgb, var(--c-warn) 14%, var(--c-surface))',
    '--btn-warn-border':      'color-mix(in srgb, var(--c-warn) 40%, transparent)',
    '--btn-warn-text':        'var(--c-warn)',
  },
  solid: {
    '--btn-secondary-bg':     'var(--c-surface)',
    '--btn-secondary-border': 'var(--c-border)',
    '--btn-secondary-text':   'var(--c-text)',
    '--btn-danger-bg':        'var(--c-danger)',
    '--btn-danger-border':    'var(--c-danger)',
    '--btn-danger-text':      '#ffffff',
    '--btn-warn-bg':          'var(--c-warn)',
    '--btn-warn-border':      'var(--c-warn)',
    '--btn-warn-text':        '#111111',
  },
  lightTinted: {
    '--btn-secondary-bg':     'var(--c-surface)',
    '--btn-secondary-border': 'var(--c-border)',
    '--btn-secondary-text':   'var(--c-text)',
    '--btn-danger-bg':        'color-mix(in srgb, var(--c-danger) 10%, var(--c-surface))',
    '--btn-danger-border':    'color-mix(in srgb, var(--c-danger) 35%, transparent)',
    '--btn-danger-text':      'var(--c-danger)',
    '--btn-warn-bg':          'color-mix(in srgb, var(--c-warn) 10%, var(--c-surface))',
    '--btn-warn-border':      'color-mix(in srgb, var(--c-warn) 35%, transparent)',
    '--btn-warn-text':        'var(--c-warn)',
  },
};

export const THEMES: Record<ThemeId, Theme> = {

  'primer-dark': {
    id: 'primer-dark', label: 'Primer Dark', group: 'reference',
    description: 'GitHub security console — recommended default for zero-trust UI',
    dark: true,
    preview: { bg: '#0D1117', surface: '#151B23', accent: '#4493F8', danger: '#FF6B6B' },
    vars: {
      '--c-bg':         '#0D1117',
      '--c-surface':    '#151B23',
      '--c-border':     '#3D444D',
      '--c-text':       '#E6EDF3',
      '--c-text-dim':   '#8D96A0',
      '--c-accent':     '#4493F8',
      '--c-accent-dim': '#2F7DD4',
      '--c-success':    '#3FB950',
      '--c-warn':       '#D29922',
      '--c-danger':     '#F85149',
      '--radius':       '6px',
      ...btnTokens.tinted,
    },
  },

  'apple-dark': {
    id: 'apple-dark', label: 'Apple HIG Dark', group: 'reference',
    description: 'macOS system colors — native feel on Mac',
    dark: true,
    preview: { bg: '#000000', surface: '#1C1C1E', accent: '#0A84FF', danger: '#FF6B6B' },
    vars: {
      '--c-bg':         '#000000',
      '--c-surface':    '#1C1C1E',
      '--c-border':     '#38383A',
      '--c-text':       '#FFFFFF',
      '--c-text-dim':   '#8E8E93',
      '--c-accent':     '#0A84FF',
      '--c-accent-dim': '#0070E0',
      '--c-success':    '#30D158',
      '--c-warn':       '#FF9F0A',
      '--c-danger':     '#FF453A',
      '--radius':       '10px',
      ...btnTokens.tinted,
    },
  },

  'fluent-dark': {
    id: 'fluent-dark', label: 'Fluent Dark', group: 'reference',
    description: 'Windows 11 Fluent 2 — enterprise neutral tones',
    dark: true,
    preview: { bg: '#202020', surface: '#2C2C2C', accent: '#4CC2FF', danger: '#FF6B6B' },
    vars: {
      '--c-bg':         '#202020',
      '--c-surface':    '#2C2C2C',
      '--c-border':     '#3D3D3D',
      '--c-text':       '#FFFFFF',
      '--c-text-dim':   '#9D9D9D',
      '--c-accent':     '#4CC2FF',
      '--c-accent-dim': '#2AADEC',
      '--c-success':    '#6CCB5F',
      '--c-warn':       '#FCE100',
      '--c-danger':     '#FF6363',
      '--radius':       '4px',
      ...btnTokens.tinted,
    },
  },

  'material-dark': {
    id: 'material-dark', label: 'Material 3 Dark', group: 'reference',
    description: 'Full semantic tokens — WCAG-verified for regulated enterprise',
    dark: true,
    preview: { bg: '#141218', surface: '#211F26', accent: '#D0BCFF', danger: '#FF6B6B' },
    vars: {
      '--c-bg':         '#141218',
      '--c-surface':    '#211F26',
      '--c-border':     '#49454F',
      '--c-text':       '#E6E0E9',
      '--c-text-dim':   '#938F99',
      '--c-accent':     '#D0BCFF',
      '--c-accent-dim': '#B69DF8',
      '--c-success':    '#78DC77',
      '--c-warn':       '#FFB74D',
      '--c-danger':     '#F2B8B5',
      '--radius':       '12px',
      ...btnTokens.tinted,
    },
  },

  'tokyo-night': {
    id: 'tokyo-night', label: 'Tokyo Night', group: 'community',
    description: 'Modern SaaS favorite — blue accent, low eye strain',
    dark: true,
    preview: { bg: '#1a1b26', surface: '#1f2335', accent: '#7aa2f7', danger: '#FF6B6B' },
    vars: {
      '--c-bg':         '#1a1b26',
      '--c-surface':    '#1f2335',
      '--c-border':     '#3b4261',
      '--c-text':       '#c0caf5',
      '--c-text-dim':   '#565f89',
      '--c-accent':     '#7aa2f7',
      '--c-accent-dim': '#5d7cd4',
      '--c-success':    '#9ece6a',
      '--c-warn':       '#e0af68',
      '--c-danger':     '#f7768e',
      '--radius':       '10px',
      ...btnTokens.tinted,
    },
  },

  'nord': {
    id: 'nord', label: 'Nord Dark', group: 'community',
    description: 'Arctic blue — enterprise security & analytics feel',
    dark: true,
    preview: { bg: '#2e3440', surface: '#3b4252', accent: '#81a1c1', danger: '#FF6B6B' },
    vars: {
      '--c-bg':         '#2e3440',
      '--c-surface':    '#3b4252',
      '--c-border':     '#4c566a',
      '--c-text':       '#eceff4',
      '--c-text-dim':   '#d8dee9',
      '--c-accent':     '#81a1c1',
      '--c-accent-dim': '#5e81ac',
      '--c-success':    '#a3be8c',
      '--c-warn':       '#ebcb8b',
      '--c-danger':     '#bf616a',
      '--radius':       '8px',
      ...btnTokens.solid,
    },
  },

  'catppuccin-mocha': {
    id: 'catppuccin-mocha', label: 'Catppuccin Mocha', group: 'community',
    description: 'Warm pastel dark — comfortable for long sessions',
    dark: true,
    preview: { bg: '#1e1e2e', surface: '#313244', accent: '#89b4fa', danger: '#FF6B6B' },
    vars: {
      '--c-bg':         '#1e1e2e',
      '--c-surface':    '#313244',
      '--c-border':     '#45475a',
      '--c-text':       '#cdd6f4',
      '--c-text-dim':   '#6c7086',
      '--c-accent':     '#89b4fa',
      '--c-accent-dim': '#6c9fe0',
      '--c-success':    '#a6e3a1',
      '--c-warn':       '#f9e2af',
      '--c-danger':     '#f38ba8',
      '--radius':       '12px',
      ...btnTokens.tinted,
    },
  },

  'primer-light': {
    id: 'primer-light', label: 'Primer Light', group: 'reference',
    description: 'GitHub security console — recommended default for zero-trust UI',
    dark: false,
    preview: { bg: '#FFFFFF', surface: '#F6F8FA', accent: '#0969DA', danger: '#CF222E' },
    vars: {
      '--c-bg':         '#FFFFFF',
      '--c-surface':    '#F6F8FA',
      '--c-border':     '#D0D7DE',
      '--c-text':       '#1F2328',
      '--c-text-dim':   '#656D76',
      '--c-accent':     '#0969DA',
      '--c-accent-dim': '#0756B8',
      '--c-success':    '#1A7F37',
      '--c-warn':       '#9A6700',
      '--c-danger':     '#CF222E',
      '--radius':       '6px',
      ...btnTokens.lightTinted,
    },
  },

  'apple-light': {
    id: 'apple-light', label: 'Apple HIG Light', group: 'reference',
    description: 'macOS system colors — native feel on Mac',
    dark: false,
    preview: { bg: '#FFFFFF', surface: '#F2F2F7', accent: '#007AFF', danger: '#CF222E' },
    vars: {
      '--c-bg':         '#FFFFFF',
      '--c-surface':    '#F2F2F7',
      '--c-border':     '#C6C6C8',
      '--c-text':       '#000000',
      '--c-text-dim':   '#6D6D72',
      '--c-accent':     '#007AFF',
      '--c-accent-dim': '#0066D6',
      '--c-success':    '#34C759',
      '--c-warn':       '#FF9500',
      '--c-danger':     '#FF3B30',
      '--radius':       '10px',
      ...btnTokens.lightTinted,
    },
  },

  'fluent-light': {
    id: 'fluent-light', label: 'Fluent Light', group: 'reference',
    description: 'Windows 11 Fluent 2 — clean neutral surface',
    dark: false,
    preview: { bg: '#F3F3F3', surface: '#FFFFFF', accent: '#0078D4', danger: '#CF222E' },
    vars: {
      '--c-bg':         '#F3F3F3',
      '--c-surface':    '#FFFFFF',
      '--c-border':     '#E0E0E0',
      '--c-text':       '#1A1A1A',
      '--c-text-dim':   '#6B6B6B',
      '--c-accent':     '#0078D4',
      '--c-accent-dim': '#005FA3',
      '--c-success':    '#107C10',
      '--c-warn':       '#8A8886',
      '--c-danger':     '#C42B1C',
      '--radius':       '4px',
      ...btnTokens.lightTinted,
    },
  },

  'material-light': {
    id: 'material-light', label: 'Material 3 Light', group: 'reference',
    description: 'Full semantic tokens — WCAG-verified for regulated enterprise',
    dark: false,
    preview: { bg: '#FEF7FF', surface: '#F3EDF7', accent: '#6750A4', danger: '#CF222E' },
    vars: {
      '--c-bg':         '#FEF7FF',
      '--c-surface':    '#F3EDF7',
      '--c-border':     '#CAC4D0',
      '--c-text':       '#1D1B20',
      '--c-text-dim':   '#49454F',
      '--c-accent':     '#6750A4',
      '--c-accent-dim': '#4F3D8A',
      '--c-success':    '#386A20',
      '--c-warn':       '#7D5700',
      '--c-danger':     '#B3261E',
      '--radius':       '12px',
      ...btnTokens.lightTinted,
    },
  },

  'nord-light': {
    id: 'nord-light', label: 'Nord Light', group: 'community',
    description: 'Arctic palette Snow Storm — bright and calm',
    dark: false,
    preview: { bg: '#ECEFF4', surface: '#E5E9F0', accent: '#5E81AC', danger: '#CF222E' },
    vars: {
      '--c-bg':         '#ECEFF4',
      '--c-surface':    '#E5E9F0',
      '--c-border':     '#D8DEE9',
      '--c-text':       '#2E3440',
      '--c-text-dim':   '#4C566A',
      '--c-accent':     '#5E81AC',
      '--c-accent-dim': '#4A6F9A',
      '--c-success':    '#A3BE8C',
      '--c-warn':       '#EBCB8B',
      '--c-danger':     '#BF616A',
      '--radius':       '8px',
      ...btnTokens.lightTinted,
    },
  },

  'catppuccin-latte': {
    id: 'catppuccin-latte', label: 'Catppuccin Latte', group: 'community',
    description: 'Warm light — soft contrast, easy on eyes in bright rooms',
    dark: false,
    preview: { bg: '#eff1f5', surface: '#e6e9ef', accent: '#1e66f5', danger: '#CF222E' },
    vars: {
      '--c-bg':         '#eff1f5',
      '--c-surface':    '#e6e9ef',
      '--c-border':     '#ccd0da',
      '--c-text':       '#4c4f69',
      '--c-text-dim':   '#8c8fa1',
      '--c-accent':     '#1e66f5',
      '--c-accent-dim': '#1555d8',
      '--c-success':    '#40a02b',
      '--c-warn':       '#df8e1d',
      '--c-danger':     '#d20f39',
      '--radius':       '12px',
      ...btnTokens.lightTinted,
    },
  },

  'solarized': {
    id: 'solarized', label: 'Solarized Light', group: 'community',
    description: 'Classic precision — scientific contrast ratios',
    dark: false,
    preview: { bg: '#fdf6e3', surface: '#eee8d5', accent: '#268bd2', danger: '#CF222E' },
    vars: {
      '--c-bg':         '#fdf6e3',
      '--c-surface':    '#eee8d5',
      '--c-border':     '#ddd6c1',
      '--c-text':       '#657b83',
      '--c-text-dim':   '#93a1a1',
      '--c-accent':     '#268bd2',
      '--c-accent-dim': '#1a6da8',
      '--c-success':    '#859900',
      '--c-warn':       '#b58900',
      '--c-danger':     '#dc322f',
      '--radius':       '8px',
      ...btnTokens.lightTinted,
    },
  },
};

export function applyTheme(id: ThemeId) {
  const theme = THEMES[id];
  if (!theme || typeof document === 'undefined') return;
  const root = document.documentElement;
  for (const [k, v] of Object.entries(theme.vars)) {
    root.style.setProperty(k, v);
  }
  const sec = theme.dark ? SEC_DARK : SEC_LIGHT;
  for (const [k, v] of Object.entries(sec)) {
    root.style.setProperty(k, v);
  }
}
