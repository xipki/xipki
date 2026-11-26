// License Apache License 2.0


import { useI18n } from '../i18n'
import React, { useEffect, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Alert,
  Button,
  ConfigProvider,
  Drawer,
  Layout,
  Menu,
  Typography,
  type MenuProps,
} from 'antd'
import {
  DashboardOutlined,
  SafetyCertificateOutlined,
  FileProtectOutlined,
  KeyOutlined,
  UserOutlined,
  CloudUploadOutlined,
  ToolOutlined,
  DatabaseOutlined,
  LockOutlined,
  ApiOutlined,
  AuditOutlined,
  FileAddOutlined,
  FileTextOutlined,
  MenuOutlined,
  TeamOutlined,
  ControlOutlined,
} from '@ant-design/icons'
import api from '../api/client'
import type { AuthUser } from '../auth'
import { selectedNavigationKey, visibleNavigationGroups, type NavigationKey } from '../navigation'
import ApplicationHeader from '../components/ApplicationHeader'
import AccountMenu from '../components/AccountMenu'
import './MainLayout.css'

const { Sider, Content } = Layout
const sidebarTheme = {
  components: {
    Menu: {
      darkGroupTitleColor: 'rgba(255, 255, 255, 0.50)',
      darkItemColor: 'rgba(255, 255, 255, 0.88)',
    },
  },
}

const icons: Record<NavigationKey, React.ReactNode> = {
  '/dashboard': <DashboardOutlined />,
  '/ca': <SafetyCertificateOutlined />,
  '/cert': <FileProtectOutlined />,
  '/cert/enroll': <FileAddOutlined />,
  '/crl': <FileTextOutlined />,
  '/profile': <ApiOutlined />,
  '/signer': <KeyOutlined />,
  '/requestor': <UserOutlined />,
  '/publisher': <CloudUploadOutlined />,
  '/keypairgen': <LockOutlined />,
  '/system': <ToolOutlined />,
  '/dbschema': <DatabaseOutlined />,
  '/audit': <AuditOutlined />,
  '/access/users': <TeamOutlined />,
  '/access/roles': <ControlOutlined />,
}

interface Props {
  children: React.ReactNode
  user: AuthUser
  onLogout: () => void
}

const MainLayout: React.FC<Props> = ({ children, user, onLogout }) => {
  const { t } = useI18n()
  const navigate = useNavigate()
  const location = useLocation()
  const [caAvailable, setCaAvailable] = useState(true)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const selectedKey = selectedNavigationKey(location.pathname)
  const menuItems: MenuProps['items'] = visibleNavigationGroups(user).map((group) => ({
    type: 'group',
    label: t(group.label),
    key: group.label,
    children: group.items.map((item) => ({
      key: item.key,
      icon: icons[item.key],
      label: t(item.label),
    })),
  }))
  const selectMenu: MenuProps['onClick'] = ({ key }) => {
    setMobileMenuOpen(false)
    navigate(key)
  }
  useEffect(() => setMobileMenuOpen(false), [location.pathname])
  useEffect(() => {
    let alive = true
    const check = () =>
      fetch('/health/ready', { signal: AbortSignal.timeout(8000) })
        .then((response) => {
          if (alive) setCaAvailable(response.ok)
        })
        .catch(() => {
          if (alive) setCaAvailable(false)
        })
    check()
    const timer = window.setInterval(check, 15000)
    return () => {
      alive = false
      window.clearInterval(timer)
    }
  }, [])

  const handleLogout = async () => {
    try {
      await api.post('/api/auth/logout')
      onLogout()
    } catch {
      /* Keep the session visible when the server could not confirm logout. */
    }
  }

  return (
    <Layout className="console-layout">
      <Sider width={232} theme="dark" className="console-desktop-nav">
        <div className="console-nav-brand">
          <Typography.Title level={4}>{t('XiPKI Management')}</Typography.Title>
        </div>
        <ConfigProvider theme={sidebarTheme}>
          <Menu
            theme="dark"
            mode="inline"
            selectedKeys={selectedKey ? [selectedKey] : []}
            items={menuItems}
            onClick={selectMenu}
          />
        </ConfigProvider>
      </Sider>
      <Layout>
        <ApplicationHeader
          brand={
            <Button
              className="console-menu-trigger"
              type="text"
              icon={<MenuOutlined />}
              aria-label={t('Open navigation')}
              title={t('Open navigation')}
              onClick={() => setMobileMenuOpen(true)}
            />
          }
        >
          <AccountMenu user={user} onLogout={handleLogout} />
        </ApplicationHeader>
        <Content className="console-content">
          {!caAvailable && (
            <Alert
              type="error"
              message={t('CA or platform database unavailable')}
              showIcon
              style={{ marginBottom: 16 }}
            />
          )}
          {children}
        </Content>
      </Layout>
      <Drawer
        title={t('XiPKI Management')}
        placement="left"
        width="min(280px, 86vw)"
        open={mobileMenuOpen}
        onClose={() => setMobileMenuOpen(false)}
        className="console-mobile-drawer"
        styles={{ body: { padding: 0 } }}
      >
        <Menu
          mode="inline"
          selectedKeys={selectedKey ? [selectedKey] : []}
          items={menuItems}
          onClick={selectMenu}
        />
      </Drawer>
    </Layout>
  )
}

export default MainLayout
