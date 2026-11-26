// License Apache License 2.0


import { useContext, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Switch,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd'
import api, { authenticationRequiredEvent } from '../../api/client'
import { AuthContext } from '../../auth'
import { useI18n } from '../../i18n'
import { useReauthentication } from '../../components/Reauthentication'
import { togglePermission, type Permission, type Role } from './roles-model'
import PermissionExplorer from './PermissionExplorer'

export default function RoleEditor({
  role,
  copy,
  catalog,
  onClose,
  onSaved,
}: {
  role?: Role
  copy?: boolean
  catalog: Permission[]
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useI18n()
  const me = useContext(AuthContext)
  const editing = !!role && !copy
  const [form] = Form.useForm()
  const { authorize, dialog } = useReauthentication()
  const [scope, setScope] = useState<'CA' | 'PLATFORM'>(role?.scope || 'CA')
  const [selected, setSelected] = useState<string[]>(role?.permissions || [])
  const [enabled, setEnabled] = useState(editing ? role!.enabled : true)
  const [confirmed, setConfirmed] = useState(false)
  const [saving, setSaving] = useState(false)
  const [tab, setTab] = useState(editing ? 'permissions' : 'basic')
  const [dependencyNotice, setDependencyNotice] = useState<{ added: string[]; removed: string[] }>()
  const before = editing ? role!.permissions : []
  const added = selected.filter((code) => !before.includes(code))
  const removed = before.filter((code) => !selected.includes(code))
  const stateChanged = editing && enabled !== role!.enabled
  const risk =
    stateChanged || added.some((code) => catalog.find((item) => item.code === code)?.highRisk)
  const available = catalog.filter((item) => item.scope === scope)
  const toggle = (code: string, checked: boolean) => {
    const next = togglePermission(selected, code, checked, catalog)
    setDependencyNotice({
      added: next.filter((value) => value !== code && !selected.includes(value)),
      removed: selected.filter((value) => value !== code && !next.includes(value)),
    })
    setSelected(next)
    setConfirmed(false)
  }
  const invalidAudit =
    selected.some((code) => ['AUDIT_READ', 'AUDIT_EXPORT', 'AUDIT_CONTEXT_READ'].includes(code)) &&
    selected.some((code) => !catalog.find((item) => item.code === code)?.auditCompatible)
  const save = async () => {
    if (saving || invalidAudit || (risk && !confirmed)) return
    const values = await form.validateFields().catch(() => undefined)
    if (!values) {
      setTab('basic')
      return
    }
    authorize(t(editing ? 'Save role changes' : 'Create role'), async () => {
      setSaving(true)
      try {
        const body = {
          displayName: values.displayName,
          description: values.description || '',
          permissions: selected,
          confirmed,
        }
        if (editing)
          await api.put(`/api/roles/${role!.name}`, { ...body, revision: role!.revision, enabled })
        else await api.post('/api/roles', { ...body, name: values.name, scope })
        message.success(t('Role saved. Permission changes revoke affected sessions.'))
        onSaved()
        if (
          editing &&
          (added.length || removed.length || stateChanged) &&
          me?.bindings?.some((binding) => binding.role === role!.name)
        )
          window.dispatchEvent(new Event(authenticationRequiredEvent))
      } finally {
        setSaving(false)
      }
    })
  }
  return (
    <>
      <Modal
        open
        title={t(editing ? 'Edit role' : copy ? 'Copy role' : 'Create role')}
        width={1100}
        className="access-modal role-editor"
        style={{ top: 24 }}
        onCancel={() => !saving && onClose()}
        footer={
          <div className="role-editor-footer">
            <Typography.Text type="secondary">
              {t('{selected} selected · +{added} / −{removed} · {users} bound users', {
                selected: selected.length,
                added: added.length,
                removed: removed.length,
                users: editing ? role!.userCount : 0,
              })}
            </Typography.Text>
            <Space>
              <Button disabled={saving} onClick={onClose}>
                {t('Cancel')}
              </Button>
              {tab === 'review' ? (
                <Button
                  type="primary"
                  loading={saving}
                  disabled={invalidAudit || (risk && !confirmed)}
                  onClick={() => void save()}
                >
                  {t('Save')}
                </Button>
              ) : (
                <Button type="primary" onClick={() => setTab('review')}>
                  {t('Review changes')}
                </Button>
              )}
            </Space>
          </div>
        }
        destroyOnClose
      >
        <Tabs
          activeKey={tab}
          onChange={setTab}
          items={[
            {
              key: 'basic',
              label: t('Basic information'),
              forceRender: true,
              children: (
                <>
                  <Form
                    form={form}
                    layout="vertical"
                    initialValues={{
                      name: editing ? role!.name : '',
                      displayName: role?.displayName || '',
                      description: role?.description || '',
                    }}
                  >
                    <div className="role-editor-fields">
                      <Form.Item
                        name="name"
                        label={t('Role code')}
                        rules={[
                          { required: true },
                          {
                            pattern: /^[A-Z][A-Z0-9_]{1,63}$/,
                            message: t(
                              'Use 2–64 uppercase letters, digits or underscores; start with a letter.',
                            ),
                          },
                        ]}
                      >
                        <Input
                          aria-label={t('Role code')}
                          disabled={editing || saving}
                          maxLength={64}
                        />
                      </Form.Item>
                      <Form.Item
                        name="displayName"
                        label={t('Display name')}
                        rules={[{ required: true, whitespace: true, max: 128 }]}
                      >
                        <Input aria-label={t('Display name')} maxLength={128} disabled={saving} />
                      </Form.Item>
                      <Form.Item label={t('Scope')}>
                        <Select
                          aria-label={t('Scope')}
                          style={{ width: 180 }}
                          value={scope}
                          disabled={editing || saving}
                          options={[
                            { value: 'CA', label: t('Granted CAs') },
                            { value: 'PLATFORM', label: t('Platform') },
                          ]}
                          onChange={(value) => {
                            setScope(value)
                            setSelected([])
                            setConfirmed(false)
                            setDependencyNotice(undefined)
                          }}
                        />
                      </Form.Item>
                    </div>
                    <Form.Item name="description" label={t('Description')}>
                      <Input.TextArea
                        aria-label={t('Description')}
                        maxLength={255}
                        rows={2}
                        disabled={saving}
                      />
                    </Form.Item>
                    {editing && !role!.builtin && (
                      <Form.Item label={t('Enabled')}>
                        <Switch
                          checked={enabled}
                          disabled={saving}
                          onChange={(value) => {
                            setEnabled(value)
                            setConfirmed(false)
                          }}
                        />
                      </Form.Item>
                    )}
                  </Form>
                  <Alert
                    type="info"
                    showIcon
                    message={t(
                      'Permissions define actions. CA and certificate profile limits are configured separately for each user grant.',
                    )}
                  />
                </>
              ),
            },
            {
              key: 'permissions',
              label: t('Permission configuration'),
              children: (
                <div className="permission-explorer">
                  {scope === 'PLATFORM' && (
                    <Alert
                      type="info"
                      showIcon
                      message={t(
                        'Shared definitions apply globally and can affect multiple CAs. CA associations are granted separately.',
                      )}
                      style={{ marginBottom: 12 }}
                    />
                  )}
                  {dependencyNotice &&
                    (dependencyNotice.added.length > 0 || dependencyNotice.removed.length > 0) && (
                      <Alert
                        type="info"
                        showIcon
                        closable
                        onClose={() => setDependencyNotice(undefined)}
                        style={{ marginBottom: 12 }}
                        message={
                          <>
                            {dependencyNotice.added.length > 0 && (
                              <div>
                                {t('Required permissions added')}:{' '}
                                {dependencyNotice.added.map((code) => t(code)).join(', ')}
                              </div>
                            )}
                            {dependencyNotice.removed.length > 0 && (
                              <div>
                                {t('Dependent permissions removed')}:{' '}
                                {dependencyNotice.removed.map((code) => t(code)).join(', ')}
                              </div>
                            )}
                          </>
                        }
                      />
                    )}
                  <PermissionExplorer
                    key={scope}
                    catalog={available}
                    selected={selected}
                    onToggle={toggle}
                    disabled={saving}
                  />
                </div>
              ),
            },
            {
              key: 'review',
              label: t('Change preview'),
              children: (
                <Space direction="vertical" style={{ width: '100%' }}>
                  {invalidAudit && (
                    <Alert
                      type="error"
                      showIcon
                      message={t('Audit permissions cannot be combined with write permissions.')}
                    />
                  )}
                  <Card size="small" title={t('Change preview')}>
                    <div>
                      {t('Bound users')}: {editing ? role!.userCount : 0}
                    </div>
                    <div>
                      {t('Scope')}: {t(scope === 'CA' ? 'Granted CAs' : 'Platform')}
                    </div>
                    {stateChanged && (
                      <div>
                        {t('Status')}: {t(role!.enabled ? 'Enabled' : 'Disabled')} →{' '}
                        {t(enabled ? 'Enabled' : 'Disabled')}
                      </div>
                    )}
                    <div>
                      {t('Added permissions')}:{' '}
                      {added.map((code) => (
                        <Tag color="green" key={code}>
                          {t(code)}
                        </Tag>
                      ))}
                    </div>
                    <div>
                      {t('Removed permissions')}:{' '}
                      {removed.map((code) => (
                        <Tag color="red" key={code}>
                          {t(code)}
                        </Tag>
                      ))}
                    </div>
                    <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
                      {t(
                        'Permission or state changes revoke all bound users’ sessions. Existing profile scopes are retained; an empty profile scope denies issuance.',
                      )}
                    </Typography.Paragraph>
                  </Card>
                  {risk && (
                    <Alert
                      type="warning"
                      showIcon
                      message={t('Confirm high-risk permissions or role state changes')}
                      description={
                        <Checkbox
                          checked={confirmed}
                          onChange={(event) => setConfirmed(event.target.checked)}
                        >
                          {t('I confirm these changes and their effect on bound users')}
                        </Checkbox>
                      }
                    />
                  )}
                </Space>
              ),
            },
          ]}
        />
      </Modal>
      {dialog}
    </>
  )
}
