import type { TagProps } from 'antd';

// Status vocabulary → antd Tag color. Shape/color both encode state.
const SUCCESS = new Set(['applied', 'pass', 'online', 'active', 'ok']);
const ERROR = new Set(['failed', 'rollback_pending', 'fail', 'revoked']);
const WARNING = new Set(['pending', 'applying', 'warning']);

/**
 * Map a status string to an antd Tag color ('success' | 'error' | 'warning' |
 * 'default'). Unknown statuses fall back to gray so nothing is ever hidden.
 */
export function tagColor(status: string): TagProps['color'] {
  if (SUCCESS.has(status)) return 'success';
  if (ERROR.has(status)) return 'error';
  if (WARNING.has(status)) return 'warning';
  return 'default';
}
