import type { Dict, MessageKey } from './en';

/**
 * `{name}` placeholder interpolation, split/join based so no regex injection.
 * Unknown placeholders are left verbatim.
 */
export function interpolate(
  template: string,
  params?: Record<string, string>,
): string {
  if (!params) return template;
  return template
    .split(/(\{[^}]+\})/g)
    .map((part) => {
      const m = /^\{([^}]+)\}$/.exec(part);
      if (m && m[1] in params) return params[m[1]];
      return part;
    })
    .join('');
}

/** Look up a key in a dictionary; a missing key falls back to the key itself. */
export function translate(
  dict: Dict,
  key: MessageKey,
  params?: Record<string, string>,
): string {
  return interpolate(dict[key], params);
}
