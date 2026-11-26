// License Apache License 2.0


import { useContext, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Form,
  Input,
  Modal,
  Popconfirm,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd'
import api from '../../api/client'
import { AuthContext, useCan } from '../../auth'
import type { Binding } from '../../access-policy'
import { useI18n } from '../../i18n'
import { useReauthentication } from '../../components/Reauthentication'
import RoleBindingsEditor from './RoleBindingsEditor'
import './access.css'

type UserRow = {
  id: number
  username: string
  displayName?: string
  enabled: boolean
  passwordChangeRequired: boolean
  bindings: Binding[]
  lastLoginAt?: string
}
export default function Users() {
  const { t, locale } = useI18n()
  const can = useCan()
  const me = useContext(AuthContext)
  const { authorize, dialog } = useReauthentication()
  const [rows, setRows] = useState<UserRow[]>([])
  const [page, setPage] = useState(0)
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [editor, setEditor] = useState<Partial<UserRow>>()
  const [grants, setGrants] = useState<UserRow>()
  const [secret, setSecret] = useState<{ username: string; password: string }>()
  const [form] = Form.useForm()
  const refresh = async () => {
    setLoading(true)
    try {
      const response = await api.get('/api/users', { params: { page, size: 25, search: query } })
      setRows(response.data.data.items)
      setHasMore(response.data.data.hasMore)
    } catch {
      /* Reported by common client. */
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => {
    void refresh()
  }, [page, query])
  const edit = (row?: UserRow) => {
    form.resetFields()
    form.setFieldsValue(row || {})
    setEditor(row || {})
  }
  const save = async (values: { username: string; displayName: string }) => {
    if (saving || !editor) return
    setSaving(true)
    try {
      if (editor.id) await api.put(`/api/users/${editor.id}`, { displayName: values.displayName })
      else {
        const response = await api.post('/api/users', values)
        setSecret({ username: values.username, password: response.data.data.temporaryPassword })
      }
      setEditor(undefined)
      form.resetFields()
      await refresh()
    } catch {
      /* The API client reports errors. */
    } finally {
      setSaving(false)
    }
  }
  const toggle = async (row: UserRow) => {
    if (saving) return
    setSaving(true)
    try {
      await api.post(`/api/users/${row.id}/status`, { enabled: !row.enabled })
      await refresh()
    } catch {
      /* Do not replay account mutations. */
    } finally {
      setSaving(false)
    }
  }
  const reset = (row: UserRow) =>
    authorize(t('Reset password for {name}', { name: row.username }), async () => {
      const response = await api.post(`/api/users/${row.id}/reset-password`)
      setSecret({ username: row.username, password: response.data.data.temporaryPassword })
      await refresh()
    })
  const revoke = async (row: UserRow) => {
    try {
      await api.post(`/api/users/${row.id}/sessions/revoke`)
      message.success(t('Sessions revoked'))
      await refresh()
    } catch {
      /* Reported by common client. */
    }
  }
  return (
    <>
      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
        <Typography.Title level={3}>{t('User management')}</Typography.Title>
        {can('USER_CREATE') && (
          <Button type="primary" onClick={() => edit()}>
            {t('Create user')}
          </Button>
        )}
      </Space>
      <Alert
        type="info"
        showIcon
        message={t(
          'New users have no business access until a super administrator assigns role grants. Disable users instead of deleting their audit identity.',
        )}
        style={{ marginBottom: 16 }}
      />
      <Space style={{ marginBottom: 16 }}>
        <Input.Search
          aria-label={t('Search users')}
          placeholder={t('Search username')}
          maxLength={128}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          onSearch={() => {
            setPage(0)
            setQuery(search)
          }}
        />
        <Button loading={loading} onClick={() => void refresh()}>
          {t('Refresh')}
        </Button>
      </Space>
      <Table<UserRow>
        rowKey="id"
        dataSource={rows}
        loading={loading}
        pagination={false}
        scroll={{ x: 1100 }}
        columns={[
          { title: t('Username'), dataIndex: 'username', width: 160 },
          { title: t('Display name'), dataIndex: 'displayName', width: 160 },
          {
            title: t('Status'),
            render: (_, row) => (
              <>
                <Tag color={row.enabled ? 'green' : 'red'}>
                  {row.enabled ? t('Enabled') : t('Disabled')}
                </Tag>
                {row.passwordChangeRequired && (
                  <Tag color="orange">{t('Password change required')}</Tag>
                )}
              </>
            ),
          },
          { title: t('Role grants'), render: (_, row) => <GrantSummary bindings={row.bindings} /> },
          {
            title: t('Last login'),
            dataIndex: 'lastLoginAt',
            render: (value) => (value ? new Date(value).toLocaleString(locale) : '—'),
          },
          {
            title: t('Actions'),
            fixed: 'right',
            width: 320,
            render: (_, row) => (
              <Space wrap>
                {can('USER_UPDATE') && (
                  <Button size="small" disabled={saving} onClick={() => edit(row)}>
                    {t('Edit')}
                  </Button>
                )}
                {can('USER_ROLE_ASSIGN') && (
                  <Button
                    size="small"
                    disabled={saving}
                    onClick={async () => {
                      try {
                        const response = await api.get(`/api/users/${row.id}`)
                        setGrants(response.data.data)
                      } catch {}
                    }}
                  >
                    {t('Role grants')}
                  </Button>
                )}
                {can('USER_STATUS_UPDATE') && (
                  <Popconfirm
                    title={
                      row.enabled
                        ? t('Disable {name}?', { name: row.username })
                        : t('Enable {name}?', { name: row.username })
                    }
                    description={t('Existing sessions will be revoked.')}
                    onConfirm={() =>
                      authorize(t('Existing sessions will be revoked.'), () => toggle(row))
                    }
                  >
                    <Button
                      size="small"
                      danger={row.enabled}
                      disabled={saving || me?.id === row.id}
                    >
                      {row.enabled ? t('Disable') : t('Enable')}
                    </Button>
                  </Popconfirm>
                )}
                {can('USER_PASSWORD_RESET') && (
                  <Button
                    size="small"
                    disabled={saving || me?.id === row.id}
                    onClick={() => reset(row)}
                  >
                    {t('Reset password')}
                  </Button>
                )}
                {can('USER_SESSION_REVOKE') && (
                  <Popconfirm
                    title={t('Revoke sessions for {name}?', { name: row.username })}
                    onConfirm={() => authorize(t('Revoke sessions'), () => revoke(row))}
                  >
                    <Button size="small" disabled={saving}>
                      {t('Revoke sessions')}
                    </Button>
                  </Popconfirm>
                )}
              </Space>
            ),
          },
        ]}
      />
      <Space style={{ marginTop: 16 }}>
        <Button disabled={page === 0 || loading} onClick={() => setPage(page - 1)}>
          {t('Previous')}
        </Button>
        <span>{t('Page {page}', { page: page + 1 })}</span>
        <Button disabled={!hasMore || loading} onClick={() => setPage(page + 1)}>
          {t('Next')}
        </Button>
      </Space>
      <Modal
        title={editor?.id ? t('Edit user') : t('Create user')}
        open={!!editor}
        onCancel={() => !saving && setEditor(undefined)}
        onOk={() => form.submit()}
        confirmLoading={saving}
      >
        <Form form={form} layout="vertical" onFinish={save}>
          <Form.Item
            name="username"
            label={t('Username')}
            rules={
              editor?.id
                ? []
                : [
                    { required: true },
                    {
                      pattern: /^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,63}$/,
                      message: t(
                        'Use 1–64 letters, digits, dots, underscores, @ or hyphens; start with a letter or digit.',
                      ),
                    },
                  ]
            }
          >
            <Input disabled={!!editor?.id} autoComplete="off" />
          </Form.Item>
          <Form.Item name="displayName" label={t('Display name')}>
            <Input maxLength={128} />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title={t('Temporary password')}
        open={!!secret}
        footer={
          <Button type="primary" onClick={() => setSecret(undefined)}>
            {t('I have saved the temporary password')}
          </Button>
        }
        onCancel={() => setSecret(undefined)}
        destroyOnClose
      >
        <Alert
          type="warning"
          showIcon
          message={t(
            'This password is displayed once. Deliver it securely; the user must change it at first login.',
          )}
          style={{ marginBottom: 16 }}
        />
        <Typography.Paragraph>
          {t('Username')}: {secret?.username}
        </Typography.Paragraph>
        <Input.TextArea
          aria-label={t('Temporary password')}
          value={secret?.password || ''}
          readOnly
          autoComplete="off"
          rows={2}
        />
      </Modal>
      {grants && (
        <RoleBindingsEditor
          key={grants.id}
          target={grants}
          onClose={() => setGrants(undefined)}
          onSaved={() => void refresh()}
        />
      )}
      {dialog}
    </>
  )
}

function GrantSummary({ bindings }: { bindings: Binding[] }) {
  const { t } = useI18n()
  const [expanded, setExpanded] = useState(false)
  if (!bindings.length) return <Typography.Text type="secondary">{t('No grants')}</Typography.Text>
  return (
    <Space direction="vertical" size={4}>
      <Typography.Text type="secondary">
        {t('{count} role grants', { count: bindings.length })}
      </Typography.Text>
      <div>
        {(expanded ? bindings : bindings.slice(0, 3)).map((binding, index) => (
          <Tag key={index} style={{ marginBottom: 4 }}>
            {t(binding.role)} ·{' '}
            {binding.scope === 'NAMED_CA'
              ? binding.caName
              : binding.scope === 'PLATFORM'
                ? t('Platform')
                : t('All current and future CAs')}
          </Tag>
        ))}
      </div>
      {bindings.length > 3 && (
        <Button type="link" size="small" onClick={() => setExpanded(!expanded)}>
          {expanded ? t('Show less') : t('Show all {count} grants', { count: bindings.length })}
        </Button>
      )}
    </Space>
  )
}
