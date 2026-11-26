// License Apache License 2.0


import { useRef, useState } from 'react'
import { Button, Dropdown } from 'antd'
import { CheckOutlined, DownOutlined, GlobalOutlined } from '@ant-design/icons'
import { useI18n } from '../i18n'
import { languageOptions, languages, normalizeLocale } from '../i18n/languages'
import './LanguageSwitcher.css'

export default function LanguageSwitcher() {
  const { locale, setLocale, t } = useI18n()
  const [open, setOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  return (
    <Dropdown
      trigger={['click']}
      placement="bottomRight"
      autoFocus
      open={open}
      onOpenChange={setOpen}
      menu={{
        selectable: true,
        selectedKeys: [locale],
        'aria-label': t('Language'),
        className: 'language-switcher-menu',
        items: languageOptions.map(({ value, label }) => ({
          key: value,
          label: (
            <span className="language-option">
              <span lang={value}>{label}</span>
              <CheckOutlined
                aria-hidden
                style={{ visibility: value === locale ? 'visible' : 'hidden' }}
              />
            </span>
          ),
        })),
        onClick: ({ key, domEvent }) => {
          // Enter selects a menu item on keydown. Prevent its native click from
          // reopening the menu after focus returns to the trigger.
          domEvent.preventDefault()
          setLocale(normalizeLocale(key))
          setOpen(false)
          triggerRef.current?.focus()
        },
      }}
    >
      <Button
        ref={triggerRef}
        type="text"
        className="language-switcher"
        aria-label={t('Language')}
        aria-haspopup="menu"
        aria-expanded={open}
        icon={<GlobalOutlined aria-hidden />}
      >
        <span lang={locale}>{languages[locale].label}</span>
        <DownOutlined className="language-switcher-chevron" aria-hidden />
      </Button>
    </Dropdown>
  )
}
