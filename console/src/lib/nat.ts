import type { DataplaneEvidence } from '../api';
import { en } from '../i18n/en';
import type { Translate } from '../i18n/language-context';

/**
 * The gateway's kernel-verified dataplane reading, as reported by its agent
 * (§7.5 evidence). The ownership scan is per device, not per route — one
 * reading covers every route and alias the gateway serves — so this is a
 * row-level pointer, never a per-route verdict.
 *
 * `t` is optional so not-yet-migrated callers still get English labels; pass a
 * translator to localize once the caller is i18n'd.
 */
export function natReading(
  evidence: DataplaneEvidence | null,
  t?: Translate,
): string {
  const label = (key: keyof typeof en) => (t ? t(key) : en[key]);
  if (!evidence || evidence.nat_rules_present == null) {
    return label('nat.notReported');
  }
  if (!evidence.nat_rules_present) {
    return label('nat.rulesAbsent');
  }
  if (evidence.nat_snat_rules_present == null) {
    return label('nat.nat');
  }
  return evidence.nat_snat_rules_present
    ? label('nat.natSnat')
    : label('nat.natSourcesKept');
}
