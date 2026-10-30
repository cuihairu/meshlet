import { createContext, useContext } from 'react';
import { en, type MessageKey } from './en';
import { interpolate } from './translate';

export type Language = 'en' | 'zh';
export type Translate = (key: MessageKey, params?: Record<string, string>) => string;

export interface LanguageContextValue {
  lang: Language;
  setLang: (lang: Language) => void;
  t: Translate;
}

// Safe default (English) — never throws, so components outside a provider
// (tests) still get a working translator. Keeps existing tests green.
const enTranslate: Translate = (key, params) => {
  const template = en[key];
  return params ? interpolate(template, params) : template;
};

const noop = () => {};

export const LanguageContext = createContext<LanguageContextValue | null>(null);

export function useLanguage(): LanguageContextValue {
  const ctx = useContext(LanguageContext);
  if (ctx) return ctx;
  return { lang: 'en', setLang: noop, t: enTranslate };
}
