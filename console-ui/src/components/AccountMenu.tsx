// License Apache License 2.0


import { useRef, useState } from 'react'
import { Avatar, Button, Dropdown } from 'antd'
import { DownOutlined, LockOutlined, LogoutOutlined, UserOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import type { AuthUser } from '../auth'
import { useI18n } from '../i18n'
import './AccountMenu.css'

export default function AccountMenu({
  user,
  onLogout,
}: {
  user: AuthUser
  onLogout: () => Promise<void>
}) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [keyboardOpen, setKeyboardOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const name = user.displayName || user.username

  return (
    <Dropdown
      trigger={['hover', 'click']}
      placement="bottomRight"
      open={open}
      autoFocus={keyboardOpen}
      mouseEnterDelay={0.15}
      mouseLeaveDelay={0.15}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) setKeyboardOpen(false)
      }}
      menu={{
        className: 'account-menu',
        'aria-label': t('Account menu'),
        selectable: false,
        items: [
          {
            key: 'account',
            icon: <UserOutlined />,
            label: t('My account'),
            disabled: busy || user.passwordChangeRequired,
          },
          { key: 'password', icon: <LockOutlined />, label: t('Change password'), disabled: busy },
          { type: 'divider' },
          { key: 'logout', icon: <LogoutOutlined />, label: t('Logout'), disabled: busy },
        ],
        onClick: async ({ key, domEvent }) => {
          domEvent.preventDefault()
          setOpen(false)
          setKeyboardOpen(false)
          triggerRef.current?.focus()
          if (key === 'logout') {
            if (busy) return
            setBusy(true)
            try {
              await onLogout()
            } finally {
              setBusy(false)
            }
          } else {
            navigate(key === 'account' ? '/account' : '/account/password')
          }
        },
      }}
    >
      <Button
        ref={triggerRef}
        type="text"
        className="account-menu-trigger"
        aria-label={t('Account menu')}
        aria-haspopup="menu"
        aria-expanded={open}
        loading={busy}
        disabled={busy}
        title={name}
        onKeyDown={(event) => {
          if (['Enter', ' ', 'ArrowDown'].includes(event.key)) {
            setKeyboardOpen(true)
            if (event.key === 'ArrowDown') {
              event.preventDefault()
              setOpen(true)
            }
          }
        }}
      >
        <Avatar size={28} icon={<UserOutlined aria-hidden />} />
        <span className="account-menu-name">{name}</span>
        <DownOutlined className="account-menu-chevron" aria-hidden />
      </Button>
    </Dropdown>
  )
}
