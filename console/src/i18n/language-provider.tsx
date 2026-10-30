import { useCallback, useMemo, useState, type ReactNode } from 'react';
import { en, type MessageKey } from './en';
import { zh } from './zh';
import { interpolate } from './translate';
import {
  LanguageContext,
  type Language,
  type Translate,
} from './language-context';

const STORAGE_KEY = 'meshlet-lang';

function initialLang(): Language {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === 'en' || stored === 'zh') return stored;
  // Follow the browser: zh* locales default to Chinese, everything else English.
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en';
}

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Language>(initialLang);

  const setLang = useCallback((next: Language) => {
    setLangState(next);
    localStorage.setItem(STORAGE_KEY, next);
  }, []);

  const t = useCallback<Translate>(
    (key: MessageKey, params?: Record<string, string>) => {
      const template = lang === 'zh' ? zh[key] : en[key];
      return params ? interpolate(template, params) : template;
    },
    [lang],
  );

  const value = useMemo(() => ({ lang, setLang, t }), [lang, setLang, t]);
  return (
    <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>
  );
}
