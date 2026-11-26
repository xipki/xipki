// License Apache License 2.0


import React, { useCallback, useEffect, useMemo } from 'react'
import { ConfigProvider } from 'antd'
import dayjs from 'dayjs'
import { I18nextProvider, useTranslation } from 'react-i18next'
import { i18n, translate, languages, normalizeLocale, type Locale, type Translate } from './catalog'
import { storedLocale, saveLocale } from './locale'

// Restore the preference before the first React render to avoid a language flash.
void i18n.changeLanguage(storedLocale())

export function I18nProvider({ children }: { children: React.ReactNode }) {
  return (
    <I18nextProvider i18n={i18n}>
      <LocalizedComponents>{children}</LocalizedComponents>
    </I18nextProvider>
  )
}

function LocalizedComponents({ children }: { children: React.ReactNode }) {
  const { locale, t } = useI18n()
  useEffect(() => {
    document.documentElement.lang = locale
    document.title = t('XiPKI CA Management')
    dayjs.locale(languages[locale].dayjs)
  }, [locale, t])
  return <ConfigProvider locale={languages[locale].antd}>{children}</ConfigProvider>
}

export function useI18n() {
  const { i18n: engine } = useTranslation()
  const locale = normalizeLocale(engine.language)
  const setLocale = useCallback(
    (next: Locale) => {
      saveLocale(normalizeLocale(next))
      void engine.changeLanguage(normalizeLocale(next))
    },
    [engine],
  )
  const t = useCallback<Translate>((key, values) => translate(locale, key, values), [locale])
  return useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t])
}
