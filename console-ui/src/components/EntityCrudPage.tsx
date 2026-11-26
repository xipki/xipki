// License Apache License 2.0


import { useI18n } from '../i18n'
import React, { useEffect, useState } from 'react'
import {
  Table,
  Button,
  Space,
  Tag,
  Popconfirm,
  message,
  Typography,
  Modal,
  Form,
  Input,
  Checkbox,
  Alert,
  Select,
  type TableColumnsType,
} from 'antd'
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons'
import { entityEditPayload } from '../api/entities'
import { useCan } from '../auth'
import { useReauthentication } from './Reauthentication'
import { systemApi } from '../api/system'
import { entityGuidance, type EntityResource } from './entity-guidance'
import { errorMessage, type EntityPayload, type EntityRecord, type FormValues } from '../types/api'

interface EntityCrudPageProps {
  title: string
  resource: EntityResource
  api: {
    list: () => Promise<{ data: { data?: EntityRecord[] } }>
    create: (data: EntityPayload) => Promise<unknown>
    update: (name: string, data: EntityPayload) => Promise<unknown>
    remove: (name: string) => Promise<unknown>
  }
  extraColumns?: TableColumnsType<EntityRecord>
  extraFormFields?: React.ReactNode
  showConf?: boolean
  showBase64Cert?: boolean
  extraActions?: (record: EntityRecord) => React.ReactNode
}

const EntityCrudPage: React.FC<EntityCrudPageProps> = ({
  title,
  resource,
  api,
  extraColumns = [],
  showConf = true,
  showBase64Cert = false,
  extraActions,
}) => {
  const { t } = useI18n()
  const guidance = entityGuidance[resource]
  const supportedTypeKey = guidance?.supportedTypeKey
  const [data, setData] = useState<EntityRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [editItem, setEditItem] = useState<EntityRecord | null>(null)
  const [confModalData, setConfModalData] = useState<string | null>(null)
  const [typeState, setTypeState] = useState<{
    status: 'loading' | 'ready' | 'error'
    values: string[]
  }>({ status: supportedTypeKey ? 'loading' : 'ready', values: guidance?.typeOptions || [] })
  const [typeRevision, setTypeRevision] = useState(0)
  const [form] = Form.useForm()
  const replaceConf = Form.useWatch('replaceConf', form)
  const selectedType = Form.useWatch('type', form)
  const can = useCan()
  const { authorize, dialog } = useReauthentication()

  useEffect(() => {
    if (!supportedTypeKey) {
      setTypeState({ status: 'ready', values: guidance?.typeOptions || [] })
      return
    }
    let current = true
    setTypeState({ status: 'loading', values: [] })
    systemApi
      .supportedTypes()
      .then((res) => {
        const values: unknown = res.data.data?.[supportedTypeKey]
        if (
          !Array.isArray(values) ||
          !values.every((value) => typeof value === 'string' && value.trim())
        )
          throw new Error('Invalid type catalog')
        if (current) setTypeState({ status: 'ready', values: [...new Set(values as string[])] })
      })
      .catch(() => {
        if (current) setTypeState({ status: 'error', values: [] })
      })
    return () => {
      current = false
    }
  }, [resource, typeRevision])

  const fetchData = () => {
    setLoading(true)
    api
      .list()
      .then((res) => setData(res.data.data || []))
      .catch((e) => message.error(errorMessage(e, t('Could not load entities'))))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchData()
  }, [])

  const openAdd = () => {
    setEditItem(null)
    form.resetFields()
    if (typeState.status === 'ready' && typeState.values.length === 1)
      form.setFieldsValue({ type: typeState.values[0] })
    setModalOpen(true)
  }

  const openEdit = (record: EntityRecord) => {
    setEditItem(record)
    form.resetFields()
    form.setFieldsValue({
      type:
        typeState.values.find((type) => type.toLowerCase() === record.type?.toLowerCase()) ||
        record.type,
      base64Cert: record.base64Cert,
      replaceConf: false,
    })
    setModalOpen(true)
  }

  const typeGuide = guidance?.types[selectedType?.toLowerCase()]
  const existingType = editItem?.type
  const typeOptions = typeState.values.map((value) => ({ value, label: value, disabled: false }))
  if (
    existingType &&
    !typeState.values.some((value) => value.toLowerCase() === existingType.toLowerCase())
  )
    typeOptions.push({
      value: existingType,
      label: t('{type} (existing; unavailable)', { type: existingType }),
      disabled: true,
    })
  const typeBlocked =
    !!guidance &&
    (!editItem || replaceConf) &&
    (typeState.status !== 'ready' || !typeState.values.length)

  const performSubmit = async (values: FormValues) => {
    if (saving) return
    setSaving(true)
    try {
      const payload = entityEditPayload(values, !!editItem)
      if (editItem) {
        await api.update(editItem.name, payload)
        message.success(t('Updated successfully'))
      } else {
        await api.create(payload)
        message.success(t('Created successfully'))
      }
      setModalOpen(false)
      form.resetFields()
      setEditItem(null)
      fetchData()
    } catch (e: unknown) {
      message.error(errorMessage(e, t('Operation failed')))
    } finally {
      setSaving(false)
    }
  }

  const handleSubmit = (values: FormValues) => {
    if (typeBlocked) return
    authorize(t('Confirm shared resource change'), () => performSubmit(values))
  }
  const handleDelete = (name: string) =>
    authorize(t('Confirm shared resource change'), async () => {
      try {
        await api.remove(name)
        message.success(t('Deleted successfully'))
        fetchData()
      } catch (e: unknown) {
        message.error(errorMessage(e, t('Delete failed')))
      }
    })

  const baseColumns: TableColumnsType<EntityRecord> = [
    { title: t('Name'), dataIndex: 'name', key: 'name', width: 200 },
    { title: t('Type'), dataIndex: 'type', key: 'type', width: 150 },
    {
      title: t('Status'),
      dataIndex: 'faulty',
      key: 'faulty',
      width: 100,
      render: (faulty: boolean) => (
        <Tag color={faulty ? 'red' : 'green'}>{faulty ? t('Faulty') : t('OK')}</Tag>
      ),
    },
    ...(showConf
      ? [
          {
            title: t('Config'),
            dataIndex: 'conf',
            key: 'conf',
            ellipsis: true,
            render: (conf: string) =>
              conf ? (
                <a onClick={() => setConfModalData(conf)}>
                  {conf.substring(0, 60)}
                  {conf.length > 60 ? '...' : ''}
                </a>
              ) : (
                t('Configuration withheld; use explicit replacement to change it')
              ),
          },
        ]
      : []),
    ...extraColumns,
    {
      title: t('Actions'),
      key: 'actions',
      width: 200,
      render: (_value: unknown, record: EntityRecord) => (
        <Space>
          {extraActions?.(record)}
          {can(`${resource}_UPDATE`) && (
            <Button size="small" onClick={() => openEdit(record)}>
              {t('Edit')}
            </Button>
          )}
          {can(`${resource}_DELETE`) && (
            <Popconfirm
              title={t('Delete {name}?', { name: record.name })}
              onConfirm={() => handleDelete(record.name)}
            >
              <Button size="small" danger>
                {t('Delete')}
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Typography.Title level={4}>{title}</Typography.Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchData}>
            {t('Refresh')}
          </Button>
          {can(`${resource}_CREATE`) && (
            <Button type="primary" icon={<PlusOutlined />} onClick={openAdd}>
              {t('Add')}
            </Button>
          )}
        </Space>
      </div>

      <Alert
        type="info"
        showIcon
        message={t(
          'Shared definitions apply globally and can affect multiple CAs. CA associations are granted separately.',
        )}
        style={{ marginBottom: 16 }}
      />
      {guidance && (
        <Typography.Paragraph type="secondary">{t(guidance.usage)}</Typography.Paragraph>
      )}
      <Table columns={baseColumns} dataSource={data} rowKey="name" loading={loading} />

      <Modal
        title={
          editItem ? t('Edit {name}', { name: editItem.name }) : t('Add {name}', { name: title })
        }
        open={modalOpen}
        onCancel={() => {
          if (!saving) {
            setModalOpen(false)
            setEditItem(null)
            form.resetFields()
          }
        }}
        onOk={() => form.submit()}
        width={700}
        confirmLoading={saving}
        okButtonProps={{ disabled: typeBlocked }}
        closable={!saving}
        maskClosable={!saving}
        destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          {!editItem && (
            <Form.Item name="name" label={t('Name')} rules={[{ required: true }]}>
              <Input
                placeholder={
                  guidance
                    ? t('Example: {value}', { value: guidance.nameExample })
                    : t('Enter name')
                }
              />
            </Form.Item>
          )}
          <Form.Item
            name="type"
            label={t('Type')}
            rules={[
              { required: true },
              {
                validator: (_, value) => {
                  if (
                    !guidance ||
                    (editItem && !replaceConf) ||
                    !value ||
                    typeState.values.includes(value)
                  )
                    return Promise.resolve()
                  return Promise.reject(new Error(t('Select an available type')))
                },
              },
            ]}
          >
            {guidance ? (
              <Select
                showSearch
                options={typeOptions}
                loading={typeState.status === 'loading'}
                placeholder={t('Select type')}
                disabled={typeState.status !== 'ready' || (!!editItem && !replaceConf)}
              />
            ) : (
              <Input placeholder={t('Enter type')} disabled={!!editItem && !replaceConf} />
            )}
          </Form.Item>
          {guidance && typeState.status === 'loading' && (
            <Typography.Paragraph>{t('Loading available types…')}</Typography.Paragraph>
          )}
          {guidance && typeState.status === 'error' && (
            <Alert
              type="error"
              showIcon
              message={t('Could not load available types')}
              action={
                <Button size="small" onClick={() => setTypeRevision((value) => value + 1)}>
                  {t('Retry loading types')}
                </Button>
              }
              style={{ marginBottom: 12 }}
            />
          )}
          {guidance && typeState.status === 'ready' && !typeState.values.length && (
            <Alert
              type="info"
              message={t('No types are registered in the CA')}
              style={{ marginBottom: 12 }}
            />
          )}
          {typeGuide && (
            <div style={{ marginBottom: 16 }}>
              <Typography.Paragraph>{t(typeGuide.description)}</Typography.Paragraph>
              <Typography.Text strong>{t('Configuration example')}</Typography.Text>
              <Typography.Paragraph
                copyable
                style={{
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  overflowWrap: 'anywhere',
                  padding: 12,
                  background: '#fafafa',
                  borderRadius: 6,
                  marginTop: 8,
                }}
              >
                {typeGuide.example}
              </Typography.Paragraph>
              <Typography.Paragraph type="secondary">{t(typeGuide.note)}</Typography.Paragraph>
            </div>
          )}
          {guidance && selectedType && !typeGuide && (
            <Typography.Paragraph type="secondary">
              {t('Use the configuration format documented by this plugin.')}
            </Typography.Paragraph>
          )}
          {editItem && (
            <>
              <Alert
                type="info"
                showIcon
                message={t(
                  'Existing configuration is preserved unless you explicitly replace it. Enter the complete new configuration, including any required secrets.',
                )}
              />
              <Form.Item name="replaceConf" valuePropName="checked">
                <Checkbox>{t('Replace configuration')}</Checkbox>
              </Form.Item>
              {editItem.conf && (
                <Button size="small" onClick={() => setConfModalData(editItem.conf || null)}>
                  {t('View public configuration')}
                </Button>
              )}
            </>
          )}
          {(!editItem || replaceConf) && (
            <Form.Item
              name="conf"
              label={t('Complete configuration')}
              rules={[{ required: !!editItem || !!guidance }]}
            >
              <Input.TextArea
                rows={6}
                placeholder={typeGuide?.example || t('Configuration')}
                style={{ fontFamily: 'monospace', fontSize: 12 }}
              />
            </Form.Item>
          )}
          {showBase64Cert && (
            <Form.Item name="base64Cert" label={t('Certificate (Base64)')}>
              <Input.TextArea
                rows={4}
                placeholder={t('Base64 encoded certificate')}
                style={{ fontFamily: 'monospace', fontSize: 12 }}
              />
            </Form.Item>
          )}
        </Form>
      </Modal>

      <Modal
        title={t('Configuration')}
        open={!!confModalData}
        onCancel={() => setConfModalData(null)}
        footer={null}
        width={700}
      >
        <Input.TextArea
          value={confModalData || ''}
          rows={15}
          readOnly
          style={{ fontFamily: 'monospace', fontSize: 12 }}
        />
      </Modal>
      {dialog}
    </div>
  )
}

export default EntityCrudPage
