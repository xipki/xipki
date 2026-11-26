// License Apache License 2.0


import { useI18n } from '../../i18n'
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
  Select,
} from 'antd'
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { profileApi } from '../../api/entities'
import { useCan } from '../../auth'
import { useReauthentication } from '../../components/Reauthentication'
import { type EntityRecord, type FormValues } from '../../types/api'

const ProfileList: React.FC = () => {
  const { t } = useI18n()
  const can = useCan()
  const { authorize, dialog } = useReauthentication()
  const [data, setData] = useState<EntityRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [form] = Form.useForm()
  const navigate = useNavigate()

  const fetchData = () => {
    setLoading(true)
    profileApi
      .list()
      .then((res) => setData(res.data.data || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleAdd = async (values: FormValues) => {
    await profileApi.create(values)
    message.success(t('Profile created'))
    setModalOpen(false)
    form.resetFields()
    fetchData()
  }

  const handleDelete = async (name: string) => {
    await profileApi.remove(name)
    message.success(t('Profile deleted'))
    fetchData()
  }

  const columns = [
    {
      title: t('Name'),
      dataIndex: 'name',
      key: 'name',
      render: (name: string) =>
        can('PROFILE_CONFIG_READ') ? (
          <a onClick={() => navigate(`/profile/${name}`)}>{name}</a>
        ) : (
          name
        ),
    },
    { title: t('Type'), dataIndex: 'type', key: 'type' },
    {
      title: t('Status'),
      dataIndex: 'faulty',
      key: 'faulty',
      render: (faulty: boolean) => (
        <Tag color={faulty ? 'red' : 'green'}>{faulty ? t('Faulty') : t('OK')}</Tag>
      ),
    },
    {
      title: t('Actions'),
      key: 'actions',
      render: (_value: unknown, record: EntityRecord) => (
        <Space>
          {can('PROFILE_CONFIG_READ') && (
            <Button size="small" onClick={() => navigate(`/profile/${record.name}`)}>
              {t(can('PROFILE_UPDATE') ? 'Edit' : 'View public configuration')}
            </Button>
          )}
          {can('PROFILE_DELETE') && (
            <Popconfirm
              title={t('Delete this profile?')}
              onConfirm={() =>
                authorize(t('Confirm shared resource change'), () => handleDelete(record.name))
              }
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
        <Typography.Title level={4}>{t('Certificate Profiles')}</Typography.Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchData}>
            {t('Refresh')}
          </Button>
          {can('PROFILE_CREATE') && (
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
              {t('Add Profile')}{' '}
            </Button>
          )}
        </Space>
      </div>

      <Table columns={columns} dataSource={data} rowKey="name" loading={loading} />

      <Modal
        title={t('Add Certificate Profile')}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={() => form.submit()}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={(values) =>
            authorize(t('Confirm shared resource change'), () => handleAdd(values))
          }
        >
          <Form.Item name="name" label={t('Name')} rules={[{ required: true }]}>
            <Input placeholder={t('e.g. tls-server')} />
          </Form.Item>
          <Form.Item name="type" label={t('Type')} rules={[{ required: true }]}>
            <Select placeholder={t('Select type')}>
              <Select.Option value="xijson">xijson</Select.Option>
              <Select.Option value="xijsonv1">{t('xijsonv1 (legacy)')}</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="conf" label={t('Configuration (JSON)')} rules={[{ required: true }]}>
            <Input.TextArea
              rows={10}
              placeholder='{"version":"v2",...}'
              style={{ fontFamily: 'monospace', fontSize: 12 }}
            />
          </Form.Item>
        </Form>
      </Modal>
      {dialog}
    </div>
  )
}

export default ProfileList
