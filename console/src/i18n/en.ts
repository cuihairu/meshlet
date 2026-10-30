// English dictionary — source of truth for message keys (MessageKey).
// Values are verbatim from the original UI literals so existing tests that
// assert English strings stay green (default language is English).
export const en = {
  'language.change': 'Change language',
  'theme.dark': 'Dark theme',
  'theme.light': 'Light theme',
  'app.loading': 'Loading…',
  'nav.networks': 'Networks',
  'nav.access': 'Access',
  'nav.devices': 'Devices',
  'nav.diagnostics': 'Diagnostics',
  'shell.networkPlaceholder': 'select network',
  'shell.networkLoading': 'loading…',
  'shell.signOut': 'Sign out',
  'shell.consoleDomains': 'console domains',
  'auth.signIn': 'Sign in',
  'auth.createFirstAdmin': 'Create first admin',
  'auth.noAdminHint': 'No admin exists yet. This form is available only once.',
  'auth.email': 'Email',
  'auth.password': 'Password',
  'auth.createAdmin': 'Create admin',
  'auth.firstRun': 'First run? Create the first admin',
  'auth.backToSignIn': 'Back to sign in',
} as const;

export type MessageKey = keyof typeof en;
export type Dict = Record<MessageKey, string>;
