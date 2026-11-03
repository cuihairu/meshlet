import { useLanguage } from '../i18n/language-context';

/** Shown by domain pages when no network is selected in the top bar. */
export function NoNetworkSelected() {
  const { t } = useLanguage();
  return <p className="muted">{t('shell.noNetworkSelected')}</p>;
}
