// License Apache License 2.0


import type { ReactNode } from 'react'
import { Layout } from 'antd'
import LanguageSwitcher from './LanguageSwitcher'
import './ApplicationHeader.css'

export default function ApplicationHeader({
  brand,
  children,
}: {
  brand?: ReactNode
  children?: ReactNode
}) {
  return (
    <Layout.Header className="application-header">
      {brand && <div className="application-header-brand">{brand}</div>}
      <div className="application-header-actions">{children}</div>
      <LanguageSwitcher />
    </Layout.Header>
  )
}
