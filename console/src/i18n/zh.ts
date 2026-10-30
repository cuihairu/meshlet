import type { Dict } from './en';

// Chinese dictionary. Typed as Dict so a missing key is a compile error —
// zh/en parity is enforced at build time, not at runtime.
export const zh: Dict = {
  'language.change': '切换语言',
  'theme.dark': '深色主题',
  'theme.light': '浅色主题',
  'app.loading': '加载中…',
  'nav.networks': '网络',
  'nav.access': '访问',
  'nav.devices': '设备',
  'nav.diagnostics': '诊断',
  'shell.networkPlaceholder': '选择网络',
  'shell.networkLoading': '加载中…',
  'shell.signOut': '退出登录',
  'shell.consoleDomains': '控制台域名',
  'auth.signIn': '登录',
  'auth.createFirstAdmin': '创建首个管理员',
  'auth.noAdminHint': '尚无管理员。此表单仅可用一次。',
  'auth.email': '邮箱',
  'auth.password': '密码',
  'auth.createAdmin': '创建管理员',
  'auth.firstRun': '首次运行？创建首个管理员',
  'auth.backToSignIn': '返回登录',
};
