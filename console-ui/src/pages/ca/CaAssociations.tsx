// License Apache License 2.0


import { useI18n } from '../../i18n'
import { useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Form,
  Input,
  message,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
} from 'antd'
import { profileApi, publisherApi, requestorApi } from '../../api/entities'
import { useCan } from '../../auth'
import api from '../../api/client'
import { useReauthentication } from '../../components/Reauthentication'
import type { CaResource } from '../../access-policy'
import { errorMessage, type EntityPayload, type FormValues } from '../../types/api'

type Kind = 'profile' | 'requestor' | 'publisher'
type Editor = { kind: Kind; name?: string; editing?: boolean }
type AssociationRow = {
  profileName?: string
  requestorName?: string
  publisherName?: string
  aliases?: string[]
  permissions?: string[]
  profiles?: string[]
  [key: string]: unknown
}
const apiFor = { profile: profileApi, requestor: requestorApi, publisher: publisherApi }
const permissionOptions = [
  'enroll_cert',
  'revoke_cert',
  'unsuspend_cert',
  'remove_cert',
  'reenroll_cert',
  'get_crl',
  'enroll_cross',
  'gen_keypair',
  'get_cert',
  'all',
].map((value) => ({ value }))
const split = (value: string | undefined) =>
  (value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
const rowName = (row: AssociationRow, field: string): string => {
  const value = row[field]
  return typeof value === 'string' ? value : ''
}

export default function CaAssociations({
  caName,
  resource = caName,
}: {
  caName: string
  resource?: CaResource
}) {
  const { t } = useI18n()
  const errorText = (e: unknown) =>
    errorMessage(e, t('Operation failed; refresh and verify the current state'))
  const can = useCan()
  const allowed = (kind: Kind, action: string) =>
    can(`CA_${kind.toUpperCase()}_${action}`, resource)
  const visibleKinds = (['profile', 'requestor', 'publisher'] as Kind[]).filter((kind) =>
    allowed(kind, 'READ'),
  )
  const canBind = (kind: Kind) =>
    allowed(kind, 'BIND') && (kind !== 'requestor' || allowed(kind, 'ACCESS_UPDATE'))
  const visibilityKey = visibleKinds.join(',')
  const { authorize, dialog } = useReauthentication()
  const [relations, setRelations] = useState<Record<Kind, AssociationRow[]>>({
    profile: [],
    requestor: [],
    publisher: [],
  })
  const [options, setOptions] = useState<Record<Kind, string[]>>({
    profile: [],
    requestor: [],
    publisher: [],
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [editor, setEditor] = useState<Editor | null>(null)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm()

  const refresh = async () => {
    setLoading(true)
    await Promise.allSettled(
      visibleKinds.map(async (kind) => {
        try {
          const response =
            kind === 'profile'
              ? await profileApi.associationsForCa(caName)
              : await apiFor[kind].getForCa(caName)
          const rows: AssociationRow[] =
            kind === 'publisher'
              ? (response.data.data || []).map((name: string) => ({ publisherName: name }))
              : response.data.data || []
          setRelations((previous) => ({ ...previous, [kind]: rows }))
        } catch (e: unknown) {
          setError(errorText(e))
        }
      }),
    )
    setLoading(false)
  }
  useEffect(() => {
    setRelations({ profile: [], requestor: [], publisher: [] })
    setError(null)
    void refresh()
  }, [caName, visibilityKey])

  const open = async (kind: Kind, row?: AssociationRow) => {
    if (!row) {
      try {
        const response = await api.get(
          `/api/ca/${encodeURIComponent(caName)}/association-options`,
          { params: { kind } },
        )
        setOptions((previous) => ({
          ...previous,
          [kind]: (response.data.data || []).map((item: { name: string }) => item.name),
        }))
      } catch {
        return
      }
    }
    form.resetFields()
    form.setFieldsValue(
      row
        ? {
            name: row.requestorName,
            permissions: row.permissions,
            profiles: (row.profiles || []).join(','),
            confirmNonAtomic: false,
          }
        : { profiles: 'all' },
    )
    setEditor({ kind, name: row?.requestorName, editing: !!row })
  }
  const save = async (values: FormValues) => {
    if (!editor || saving) return
    if (typeof values.name !== 'string' && !editor.editing) return
    setSaving(true)
    setError(null)
    try {
      if (editor.kind === 'requestor') {
        const body: EntityPayload = {
          permissions: values.permissions,
          profiles: split(typeof values.profiles === 'string' ? values.profiles : undefined),
          ...(editor.editing ? { confirmNonAtomic: values.confirmNonAtomic === true } : {}),
        }
        if (editor.editing) await requestorApi.updateForCa(editor.name!, caName, body)
        else await requestorApi.addToCa(values.name as string, caName, body)
      } else if (editor.kind === 'profile') {
        await profileApi.addToCa(values.name as string, caName, {
          aliases: split(typeof values.aliases === 'string' ? values.aliases : undefined),
        })
      } else await publisherApi.addToCa(values.name as string, caName)
      message.success(editor.editing ? t('Association updated') : t('Association added'))
      setEditor(null)
      form.resetFields()
    } catch (e: unknown) {
      setError(errorText(e))
      message.error(errorText(e), 10)
      // A failed remove/add may have changed state. Close the editor to prevent replay.
      if (editor.editing) {
        setEditor(null)
        form.resetFields()
      }
    } finally {
      setSaving(false)
      await refresh()
    }
  }
  const unbind = async (kind: Kind, name: string) => {
    if (saving) return
    setSaving(true)
    setError(null)
    try {
      await apiFor[kind].removeFromCa(name, caName)
      message.success(t('Association removed'))
    } catch (e: unknown) {
      setError(errorText(e))
      message.error(errorText(e), 10)
    } finally {
      setSaving(false)
      await refresh()
    }
  }

  if (!visibleKinds.length) return null
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      {error && <Alert type="error" showIcon message={error} />}
      <Button
        onClick={() => {
          setError(null)
          void refresh()
        }}
        disabled={saving}
        loading={loading}
      >
        {t('Refresh associations')}
      </Button>
      {visibleKinds.map((kind) => {
        const nameField = `${kind}Name`
        return (
          <Card
            key={kind}
            title={
              {
                profile: t('Certificate templates'),
                requestor: t('Requestors'),
                publisher: t('Publishers'),
              }[kind]
            }
            extra={
              canBind(kind) && (
                <Button onClick={() => void open(kind)} disabled={saving || loading}>
                  {t('Bind {kind}', { kind: t(kind) })}
                </Button>
              )
            }
          >
            {kind === 'requestor' && (
              <Alert
                type="info"
                showIcon
                message={t(
                  'These permissions authorize external XiPKI clients. They are separate from Web user roles and the management TLS identity.',
                )}
                style={{ marginBottom: 12 }}
              />
            )}
            <Table
              size="small"
              rowKey={nameField}
              loading={loading}
              dataSource={relations[kind]}
              pagination={false}
              columns={[
                { title: t('Name'), dataIndex: nameField },
                ...(kind === 'profile'
                  ? [
                      {
                        title: t('Aliases'),
                        dataIndex: 'aliases',
                        render: (v: string[]) => (v || []).map((a) => <Tag key={a}>{a}</Tag>),
                      },
                    ]
                  : []),
                ...(kind === 'requestor' && allowed(kind, 'ACCESS_READ')
                  ? [
                      {
                        title: t('Permissions'),
                        dataIndex: 'permissions',
                        render: (v: string[]) => (v || []).join(', '),
                      },
                      {
                        title: t('Allowed profiles'),
                        dataIndex: 'profiles',
                        render: (v: string[]) => (v?.length ? v.join(', ') : t('None')),
                      },
                    ]
                  : []),
                {
                  title: t('Actions'),
                  render: (_value: unknown, row: AssociationRow) => (
                    <Space>
                      {kind === 'requestor' && allowed(kind, 'ACCESS_UPDATE') && (
                        <Button size="small" disabled={saving} onClick={() => void open(kind, row)}>
                          {t('Adjust')}
                        </Button>
                      )}
                      {allowed(kind, 'UNBIND') && (
                        <Popconfirm
                          title={t('Unbind {name} from {ca}?', {
                            name: rowName(row, nameField),
                            ca: caName,
                          })}
                          description={t('The global entity will be kept.')}
                          onConfirm={() =>
                            kind === 'requestor'
                              ? authorize(t('Unbind'), () => unbind(kind, rowName(row, nameField)))
                              : unbind(kind, rowName(row, nameField))
                          }
                        >
                          <Button size="small" danger disabled={saving}>
                            {t('Unbind')}
                          </Button>
                        </Popconfirm>
                      )}
                    </Space>
                  ),
                },
              ]}
            />
          </Card>
        )
      })}
      <Modal
        title={
          editor?.editing
            ? t('Adjust {name} association', { name: editor.name || '' })
            : t('Bind {kind} to {ca}', { kind: t(editor?.kind || ''), ca: caName })
        }
        open={!!editor}
        confirmLoading={saving}
        closable={!saving}
        maskClosable={!saving}
        onCancel={() => {
          if (!saving) {
            setEditor(null)
            form.resetFields()
          }
        }}
        onOk={() => form.submit()}
        destroyOnClose
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={(values) =>
            editor?.kind === 'requestor'
              ? authorize(t('Confirm external client access change'), () => save(values))
              : save(values)
          }
        >
          {!editor?.editing && (
            <Form.Item name="name" label={t('Name')} rules={[{ required: true }]}>
              <Select
                showSearch
                options={(editor ? options[editor.kind] : [])
                  .filter(
                    (name) =>
                      !relations[editor!.kind].some(
                        (row) =>
                          rowName(row, `${editor!.kind}Name`).toLowerCase() === name.toLowerCase(),
                      ),
                  )
                  .map((value) => ({ value }))}
              />
            </Form.Item>
          )}
          {editor?.kind === 'profile' && (
            <Form.Item name="aliases" label={t('Optional aliases (comma separated)')}>
              <Input />
            </Form.Item>
          )}
          {editor?.kind === 'requestor' && (
            <>
              <Form.Item name="permissions" label={t('Permissions')} rules={[{ required: true }]}>
                <Select mode="multiple" options={permissionOptions} />
              </Form.Item>
              <Form.Item
                name="profiles"
                label={t('Allowed profiles (comma separated, all, or empty for none)')}
              >
                <Input />
              </Form.Item>
              {editor.editing && (
                <>
                  <Alert
                    type="warning"
                    showIcon
                    message={t(
                      'This change first removes the current association, then adds the replacement. It is not atomic: failure may leave the requestor unbound. No rollback or automatic retry is performed.',
                    )}
                  />
                  <Form.Item
                    name="confirmNonAtomic"
                    valuePropName="checked"
                    rules={[
                      {
                        validator: (_, value) =>
                          value
                            ? Promise.resolve()
                            : Promise.reject(new Error(t('Confirm the non-atomic change'))),
                      },
                    ]}
                  >
                    <Checkbox>
                      {t('I understand the association may be removed if replacement fails')}
                    </Checkbox>
                  </Form.Item>
                </>
              )}
            </>
          )}
        </Form>
      </Modal>
      {dialog}
    </Space>
  )
}
