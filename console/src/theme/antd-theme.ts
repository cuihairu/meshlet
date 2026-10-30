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
          fontSize: 16,
          lineHeight: 1.6,
          borderRadius: 8,
        },
  };
}
