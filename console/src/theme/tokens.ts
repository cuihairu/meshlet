/**
 * meshlet console — design tokens (single source of truth).
 *
 * Every color / type-scale value that the antd theme AND the hand-rolled CSS
 * consume lives here. [ThemeProvider] injects them as CSS custom properties on
 * <html>; [antdThemeConfig] reads the same module. theme.css only holds the
 * non-duplicated structural scale (fonts, spacing, shadows) and color-scheme.
 *
 * Brand accent stays the green from 918542b (#22c55e dark / #16a34a light).
 * Status-pill styles are load-bearing and never renamed.
 */

export type Theme = 'dark' | 'light';

export interface Tokens {
  /** Surfaces. */
  bg: string;
  surface: string;
  surface2: string;
  border: string;
  borderStrong: string;

  /** Text. */
  text: string;
  textStrong: string;
  mutedC: string;

  /** Brand + semantics (AA on their fills). */
  accent: string;
  /** "R G B" triplet, consumed as `rgb(var(--accent-rgb) / a)`. */
  accentRgb: string;
  accentStrong: string;
  onAccent: string;
  info: string;
  warn: string;
  danger: string;
  dangerStrong: string;

  /** Type + radius shared with antd. */
  fontSize: number;
  lineHeight: number;
  radius: number;

  /** antd-only status text/fill pairs pinned to AA on pale fills. */
  antdColorTextSecondary: string;
  antdColorBorder: string;
  antdColorSuccess?: string;
  antdColorSuccessBg?: string;
  antdColorWarning?: string;
  antdColorWarningBg?: string;
}

export const darkTokens: Tokens = {
  bg: '#0f172a',
  surface: '#1e293b',
  surface2: '#272f42',
  border: '#334155',
  borderStrong: '#475569',

  text: '#e2e8f0',
  textStrong: '#f8fafc',
  mutedC: '#94a3b8',

  accent: '#22c55e',
  accentRgb: '34 197 94',
  accentStrong: '#4ade80',
  onAccent: '#0f172a',
  info: '#60a5fa',
  warn: '#f59e0b',
  danger: '#f87171',
  dangerStrong: '#ef4444',

  fontSize: 16,
  lineHeight: 1.6,
  radius: 8,

  antdColorTextSecondary: '#a3b2c7',
  antdColorBorder: '#3f4f68',
};

export const lightTokens: Tokens = {
  bg: '#ffffff',
  surface: '#f8fafc',
  surface2: '#eef2f7',
  border: '#cbd5e1',
  borderStrong: '#94a3b8',

  text: '#1e293b',
  textStrong: '#0f172a',
  mutedC: '#475569',

  accent: '#16a34a',
  accentRgb: '22 163 74',
  accentStrong: '#15803d',
  onAccent: '#ffffff',
  info: '#2563eb',
  warn: '#b45309',
  danger: '#dc2626',
  dangerStrong: '#dc2626',

  fontSize: 16,
  lineHeight: 1.6,
  radius: 8,

  antdColorTextSecondary: '#475569',
  antdColorBorder: '#cbd5e1',
  // Semantic status text on their pale fills: antd's success (#52c41a) and
  // warning (#d48806) greens fail WCAG AA (2.2:1 / 3.4:1) on light
  // backgrounds. Pin text + fill pairs to AA-compliant shades — antd derives
  // the fill as a tint of the seed, so both must be set. Brand primary is
  // untouched (colorPrimary above).
  antdColorSuccess: '#15803d',
  antdColorSuccessBg: '#f0fdf4',
  antdColorWarning: '#b45309',
  antdColorWarningBg: '#fffbeb',
};

export function tokensFor(theme: Theme): Tokens {
  return theme === 'dark' ? darkTokens : lightTokens;
}

/** CSS custom-property names → token keys, in the order we set them on <html>. */
const CSS_VAR_MAP: Array<[string, keyof Tokens]> = [
  ['--bg', 'bg'],
  ['--surface', 'surface'],
  ['--surface-2', 'surface2'],
  ['--border', 'border'],
  ['--border-strong', 'borderStrong'],
  ['--text', 'text'],
  ['--text-strong', 'textStrong'],
  ['--muted-c', 'mutedC'],
  ['--accent', 'accent'],
  ['--accent-rgb', 'accentRgb'],
  ['--accent-strong', 'accentStrong'],
  ['--on-accent', 'onAccent'],
  ['--info', 'info'],
  ['--warn', 'warn'],
  ['--danger', 'danger'],
  ['--danger-strong', 'dangerStrong'],
];

/** Applies the theme's token values as CSS custom properties on <html>. */
export function applyCssTokens(theme: Theme): void {
  const t = tokensFor(theme);
  const root = document.documentElement.style;
  for (const [prop, key] of CSS_VAR_MAP) {
    root.setProperty(prop, String(t[key]));
  }
  root.setProperty('color-scheme', theme);
}
