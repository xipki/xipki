// License Apache License 2.0


import { useState } from 'react'
import { Button, Modal, Space, Tag, Typography } from 'antd'
import { useI18n } from '../../i18n'
import PermissionExplorer from './PermissionExplorer'
import type { Permission } from './roles-model'

export default function PermissionSummary({
  permissions,
  catalog,
  title,
}: {
  permissions: string[]
  catalog: Permission[]
  title: string
}) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  return (
    <>
      <Space direction="vertical" size={4}>
        <Space wrap>
          <Typography.Text type="secondary">
            {t('{count} permissions', { count: permissions.length })}
          </Typography.Text>
          {!!permissions.length && (
            <Button type="link" size="small" onClick={() => setOpen(true)}>
              {t('View details')}
            </Button>
          )}
        </Space>
        <div>
          {permissions.slice(0, 3).map((code) => (
            <Tag key={code}>{t(code)}</Tag>
          ))}
          {permissions.length > 3 && <Tag>+{permissions.length - 3}</Tag>}
        </div>
      </Space>
      {open && (
        <Modal
          open
          title={title}
          width={1000}
          className="access-modal permission-details-modal"
          style={{ top: 24 }}
          onCancel={() => setOpen(false)}
          footer={<Button onClick={() => setOpen(false)}>{t('Close')}</Button>}
        >
          <PermissionExplorer catalog={catalog} selected={permissions} />
        </Modal>
      )}
    </>
  )
}
