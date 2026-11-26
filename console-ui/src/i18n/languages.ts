// License Apache License 2.0


import type { Locale as AntdLocale } from 'antd/es/locale'
import antdEnglish from 'antd/locale/en_US.js'
import antdChinese from 'antd/locale/zh_CN.js'
import 'dayjs/locale/zh-cn.js'
import enCommon from './locales/en-US/common.json' with { type: 'json' }
import enAccess from './locales/en-US/access.json' with { type: 'json' }
import enCa from './locales/en-US/ca.json' with { type: 'json' }
import enCertificates from './locales/en-US/certificates.json' with { type: 'json' }
import enResources from './locales/en-US/resources.json' with { type: 'json' }
import enSystem from './locales/en-US/system.json' with { type: 'json' }
import enGuide from './locales/en-US/guide.json' with { type: 'json' }
import zhCommon from './locales/zh-CN/common.json' with { type: 'json' }
import zhAccess from './locales/zh-CN/access.json' with { type: 'json' }
import zhCa from './locales/zh-CN/ca.json' with { type: 'json' }
import zhCertificates from './locales/zh-CN/certificates.json' with { type: 'json' }
import zhResources from './locales/zh-CN/resources.json' with { type: 'json' }
import zhSystem from './locales/zh-CN/system.json' with { type: 'json' }
import zhGuide from './locales/zh-CN/guide.json' with { type: 'json' }

// Ant Design's CommonJS locale exports have one extra default wrapper in native
// Node ESM (language-pack checks), while Vite already unwraps them for the browser.
function componentLocale(value: AntdLocale | { default: AntdLocale }): AntdLocale {
  return 'default' in value ? value.default : value
}

/** Add a language here: labels, bundled translations and UI/date configuration. */
export const languages = {
  'en-US': {
    label: 'English',
    antd: componentLocale(antdEnglish),
    dayjs: 'en',
    messages: {
      common: enCommon,
      access: enAccess,
      ca: enCa,
      certificates: enCertificates,
      resources: enResources,
      system: enSystem,
      guide: enGuide,
    },
  },
  'zh-CN': {
    label: '简体中文',
    antd: componentLocale(antdChinese),
    dayjs: 'zh-cn',
    messages: {
      common: zhCommon,
      access: zhAccess,
      ca: zhCa,
      certificates: zhCertificates,
      resources: zhResources,
      system: zhSystem,
      guide: zhGuide,
    },
  },
} as const

export type Locale = keyof typeof languages
export const defaultLocale: Locale = 'en-US'
export const localeStorageKey = 'xipki.locale'
export const languageOptions = Object.entries(languages).map(([value, definition]) => ({
  value,
  label: definition.label,
}))
export const normalizeLocale = (value: string | null): Locale =>
  value !== null && Object.prototype.hasOwnProperty.call(languages, value)
    ? (value as Locale)
    : defaultLocale
