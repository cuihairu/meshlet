/** Localized timestamp for ISO strings; '—' for null and unparseable input. */
export function formatTime(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** Byte count for readings (R-DIAG-2: raw values are data, not UI labels). */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)}M`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)}G`;
}
