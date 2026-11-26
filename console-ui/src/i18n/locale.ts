// License Apache License 2.0


import {
  defaultLocale,
  localeStorageKey,
  normalizeLocale,
  translate,
  type Locale,
  type Translate,
} from './catalog.ts'

export function storedLocale(): Locale {
  try {
    return normalizeLocale(localStorage.getItem(localeStorageKey))
  } catch {
    return defaultLocale
  }
}

let currentLocale = storedLocale()

export function saveLocale(locale: Locale) {
  currentLocale = locale
  try {
    localStorage.setItem(localeStorageKey, locale)
  } catch {
    /* Switching still works without browser storage. */
  }
}

// API interceptors resolve the selected language when a notification is emitted.
export const translateNotification: Translate = (key, values) =>
  translate(currentLocale, key, values)
