// License Apache License 2.0


import { useCallback, useEffect, useState } from 'react'
import { Alert, Button, Input, Modal, Space, Table, Tag, Typography, message } from 'antd'
import api from '../../api/client'
import { useCan } from '../../auth'
import { useI18n } from '../../i18n'
import { useReauthentication } from '../../components/Reauthentication'
import RoleEditor from './RoleEditor'
import PermissionSummary from './PermissionSummary'
import type { Permission, Role } from './roles-model'
export type { Role } from './roles-model'

export default function Roles() {
  const { t } = useI18n()
  const can = useCan()
  const { authorize, dialog } = useReauthentication()
  const [roles, setRoles] = useState<Role[]>([])
  const [catalog, setCatalog] = useState<Permission[]>([])
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [search, setSearch] = useState('')
  const [editor, setEditor] = useState<{ role?: Role; copy?: boolean }>()
  const load = useCallback(async () => {
    setLoading(true)
    setFailed(false)
    try {
      const [roleResponse, permissionResponse] = await Promise.all([
        api.get('/api/roles'),
        api.get('/api/permissions'),
      ])
      setRoles(roleResponse.data.data)
      setCatalog(permissionResponse.data.data)
    } catch {
      setFailed(true)
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => {
    void load()
  }, [load])
  const remove = (role: Role) =>
    Modal.confirm({
      title: t('Delete role {name}?', { name: role.displayName }),
      content: t(
        'Only unassigned custom roles can be deleted. Deleted role codes cannot be reused.',
      ),
      okText: t('Delete'),
      okButtonProps: { danger: true },
      onOk: () => {
        authorize(t('Delete role {name}?', { name: role.displayName }), async () => {
          await api.delete(`/api/roles/${role.name}`, { params: { revision: role.revision } })
          message.success(t('Role deleted'))
          await load()
        })
      },
    })
  return (
    <>
      <Typography.Title level={3}>{t('Roles and permissions')}</Typography.Title>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message={t(
          'Role permissions are saved in the database. Assign each role with CA and profile scopes in User management.',
        )}
      />
      {failed && (
        <Alert
          type="error"
          showIcon
          message={t('Could not load authorization options. Close and retry.')}
          action={<Button onClick={() => void load()}>{t('Refresh')}</Button>}
        />
      )}
      <Space wrap style={{ marginBottom: 16 }}>
        <Input.Search
          aria-label={t('Search roles')}
          placeholder={t('Search roles')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          allowClear
        />
        {can('ROLE_MANAGE') && (
          <Button type="primary" disabled={loading || failed} onClick={() => setEditor({})}>
            {t('Create role')}
          </Button>
        )}
      </Space>
      <Table<Role>
        rowKey="name"
        loading={loading}
        scroll={{ x: 1100 }}
        dataSource={roles.filter((role) =>
          [role.name, role.displayName, t(role.displayName)].some((value) =>
            value.toLowerCase().includes(search.toLowerCase()),
          ),
        )}
        pagination={{ pageSize: 10 }}
        columns={[
          {
            title: t('Role'),
            dataIndex: 'name',
            width: 210,
            render: (_, role) => (
              <>
                <strong>{t(role.displayName)}</strong>
                <div>
                  <Typography.Text type="secondary">{role.name}</Typography.Text>
                </div>
                <div>{role.description === role.name ? '' : role.description}</div>
              </>
            ),
          },
          {
            title: t('Type'),
            width: 180,
            render: (_, role) => (
              <>
                <Tag>{t(role.builtin ? 'Built-in' : 'Custom')}</Tag>
              </>
            ),
          },
          {
            title: t('Scope'),
            dataIndex: 'scope',
            width: 130,
            render: (scope) => (scope === 'PLATFORM' ? t('Platform') : t('Granted CAs')),
          },
          {
            title: t('Status'),
            width: 100,
            render: (_, role) => (
              <Tag color={role.enabled ? 'green' : 'default'}>
                {t(role.enabled ? 'Enabled' : 'Disabled')}
              </Tag>
            ),
          },
          { title: t('Bound users'), dataIndex: 'userCount', width: 100 },
          {
            title: t('Permissions'),
            dataIndex: 'permissions',
            width: 300,
            render: (permissions: string[], role) => (
              <PermissionSummary
                permissions={permissions}
                catalog={catalog}
                title={`${t(role.displayName)} · ${t('Permissions')}`}
              />
            ),
          },
          ...(can('ROLE_MANAGE')
            ? [
                {
                  title: t('Actions'),
                  width: 170,
                  render: (_: unknown, role: Role) =>
                    role.name === 'SUPER_ADMIN' ? (
                      <Typography.Text type="secondary">
                        {t('Protected recovery role')}
                      </Typography.Text>
                    ) : (
                      <Space wrap>
                        <Button size="small" onClick={() => setEditor({ role })}>
                          {t('Edit')}
                        </Button>
                        <Button size="small" onClick={() => setEditor({ role, copy: true })}>
                          {t('Copy role')}
                        </Button>
                        {!role.builtin && (
                          <Button
                            size="small"
                            danger
                            disabled={role.userCount > 0}
                            onClick={() => remove(role)}
                          >
                            {t('Delete')}
                          </Button>
                        )}
                      </Space>
                    ),
                },
              ]
            : []),
        ]}
      />
      {editor && (
        <RoleEditor
          role={editor.role}
          copy={editor.copy}
          catalog={catalog}
          onClose={() => setEditor(undefined)}
          onSaved={() => {
            setEditor(undefined)
            void load()
          }}
        />
      )}
      {dialog}
    </>
  )
}
