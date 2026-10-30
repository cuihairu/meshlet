import { Button } from 'antd';
import { MoonOutlined, SunOutlined } from '@ant-design/icons';
import { useLanguage } from '../i18n/language-context';
import { useTheme } from './theme-context';

/** Top-bar theme toggle: switches dark <-> light, persists the choice. */
export function ThemeSwitch() {
  const { theme, setTheme } = useTheme();
  const { t } = useLanguage();
  const dark = theme === 'dark';
  return (
    <Button
      type="text"
      aria-label={dark ? t('theme.light') : t('theme.dark')}
      onClick={() => setTheme(dark ? 'light' : 'dark')}
      icon={dark ? <MoonOutlined /> : <SunOutlined />}
    />
  );
}
