import { theme as antdTheme } from 'antd';
import type { ThemeConfig } from 'antd';
import { tokensFor, type Theme } from './tokens';

/**
 * antd v6 theme config for the current app theme. Reads the same token module
 * that ThemeProvider injects into theme.css, so the two never drift.
 */
export function antdThemeConfig(theme: Theme): ThemeConfig {
  const dark = theme === 'dark';
  const t = tokensFor(theme);
  return {
    algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
    token: {
      colorPrimary: t.accent,
      colorBgBase: t.bg,
      colorBgContainer: t.surface,
      colorText: t.textStrong,
      colorTextSecondary: t.antdColorTextSecondary,
      colorBorder: t.antdColorBorder,
      ...(dark
        ? {}
        : {
            colorSuccess: t.antdColorSuccess,
            colorSuccessBg: t.antdColorSuccessBg,
            colorWarning: t.antdColorWarning,
            colorWarningBg: t.antdColorWarningBg,
          }),
      fontSize: t.fontSize,
      lineHeight: t.lineHeight,
      borderRadius: t.radius,
    },
  };
}
