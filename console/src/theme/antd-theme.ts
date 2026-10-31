import { theme as antdTheme } from 'antd';
import type { ThemeConfig } from 'antd';
import type { Theme } from './theme-context';

/**
 * antd v6 theme config for the current app theme. Mirrors the CSS token set in
 * theme.css so antd components and the hand-rolled layout stay consistent.
 */
export function antdThemeConfig(theme: Theme): ThemeConfig {
  const dark = theme === 'dark';
  return {
    algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
    token: dark
      ? {
          colorPrimary: '#22c55e',
          colorBgBase: '#0f172a',
          colorBgContainer: '#1e293b',
          colorText: '#f8fafc',
          colorTextSecondary: '#a3b2c7',
          colorBorder: '#3f4f68',
          fontSize: 16,
          lineHeight: 1.6,
          borderRadius: 8,
        }
      : {
          colorPrimary: '#16a34a',
          colorBgBase: '#ffffff',
          colorBgContainer: '#f8fafc',
          colorText: '#0f172a',
          colorTextSecondary: '#475569',
          colorBorder: '#cbd5e1',
          // Semantic status text on their pale fills: antd's success (#52c41a)
          // and warning (#d48806) greens fail WCAG AA (2.2:1 / 3.4:1) on light
          // backgrounds. Pin text + fill pairs to AA-compliant shades — antd
          // derives the fill as a tint of the seed, so both must be set.
          // Brand primary is untouched (colorPrimary above).
          colorSuccess: '#15803d',
          colorSuccessBg: '#f0fdf4',
          colorWarning: '#b45309',
          colorWarningBg: '#fffbeb',
          fontSize: 16,
          lineHeight: 1.6,
          borderRadius: 8,
        },
  };
}
