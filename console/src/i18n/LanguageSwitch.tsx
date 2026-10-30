import { Button, Dropdown } from 'antd';
import { GlobalOutlined } from '@ant-design/icons';
import { useLanguage, type Language } from './language-context';

const ITEMS = [
  { key: 'en', label: 'English' },
  { key: 'zh', label: '中文' },
];

/** VitePress-style language toggle: globe icon in the top bar, endonym labels. */
export function LanguageSwitch() {
  const { lang, setLang, t } = useLanguage();
  return (
    <Dropdown
      menu={{
        items: ITEMS,
        selectable: true,
        selectedKeys: [lang],
        onClick: ({ key }) => setLang(key as Language),
      }}
    >
      <Button type="text" aria-label={t('language.change')} icon={<GlobalOutlined />} />
    </Dropdown>
  );
}
