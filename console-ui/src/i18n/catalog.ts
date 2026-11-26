// License Apache License 2.0


import { createInstance, type Resource } from 'i18next'
import { initReactI18next } from 'react-i18next'
import { languages, defaultLocale, normalizeLocale, type Locale } from './languages.ts'

export {
  languages,
  defaultLocale,
  normalizeLocale,
  localeStorageKey,
  type Locale,
} from './languages.ts'
export type Translate = (message: string, values?: Record<string, string | number>) => string

export const resources: Resource = Object.fromEntries(
  Object.entries(languages).map(([code, definition]) => [code, definition.messages]),
)

export function createTranslationEngine(packs: Resource = resources) {
  const engine = createInstance()
  const namespaces = [...new Set(Object.values(packs).flatMap((modules) => Object.keys(modules)))]
  // Resources ship inside the application/image, so initialization is synchronous
  // and language changes never depend on a translation service or network request.
  void engine.use(initReactI18next).init({
    resources: packs,
    lng: defaultLocale,
    fallbackLng: defaultLocale,
    supportedLngs: Object.keys(packs),
    load: 'currentOnly',
    ns: namespaces,
    defaultNS: 'common',
    fallbackNS: namespaces.filter((namespace) => namespace !== 'common'),
    initAsync: false,
    keySeparator: false,
    nsSeparator: false,
    returnNull: false,
    returnEmptyString: false,
    // Existing pages use English source keys and {name} placeholders. React
    // escapes rendered text; substitutions must remain literal, including $t().
    interpolation: { prefix: '{', suffix: '}', escapeValue: false, skipOnVariables: true },
    react: { useSuspense: false },
  })
  return engine
}

export const i18n = createTranslationEngine()

/** Compatibility entry point for pages and API notifications, backed by i18next. */
export function translate(
  locale: Locale,
  message: string,
  values: Record<string, string | number> = {},
): string {
  // Names and server diagnostics are data, not translation templates. In
  // particular, do not interpret i18next nesting syntax in unknown diagnostics.
  if (!i18n.exists(message, { lng: normalizeLocale(locale) })) return message
  return i18n.t(message, {
    lng: normalizeLocale(locale),
    defaultValue: message,
    // Keep user data out of i18next options such as lng, ns and defaultValue.
    replace: values,
    ...(typeof values.count === 'number' ? { count: values.count } : {}),
  })
}
