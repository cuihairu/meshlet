import type { DataplaneEvidence } from '../api';

/**
 * The gateway's kernel-verified dataplane reading, as reported by its agent
 * (§7.5 evidence). The ownership scan is per device, not per route — one
 * reading covers every route and alias the gateway serves — so this is a
 * row-level pointer, never a per-route verdict.
 */
export function natReading(evidence: DataplaneEvidence | null): string {
  if (!evidence || evidence.nat_rules_present == null) {
    return 'not reported';
  }
  if (!evidence.nat_rules_present) {
    return 'rules absent';
  }
  if (evidence.nat_snat_rules_present == null) {
    return 'nat';
  }
  return evidence.nat_snat_rules_present ? 'nat + snat' : 'nat (sources kept)';
}
