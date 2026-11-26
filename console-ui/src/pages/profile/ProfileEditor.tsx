// License Apache License 2.0


import { useI18n } from '../../i18n'
import React, { useEffect, useRef, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Card, Button, Input, Form, Select, Spin, message, Typography, Space } from 'antd'
import { ArrowLeftOutlined, SaveOutlined } from '@ant-design/icons'
import { profileApi } from '../../api/entities'
import { useCan } from '../../auth'
import { useReauthentication } from '../../components/Reauthentication'
import { errorMessage, type EntityRecord, type FormValues } from '../../types/api'

const ProfileEditor: React.FC = () => {
  const { t } = useI18n()
  const can = useCan()
  const { name } = useParams<{ name: string }>()
  const { authorize, dialog } = useReauthentication(name)
  const identity = useRef({ name, revision: 0 })
  if (identity.current.name !== name)
    identity.current = { name, revision: identity.current.revision + 1 }
  const revision = identity.current.revision
  const alive = useRef(true)
  const currentRoute = () =>
    alive.current && identity.current.name === name && identity.current.revision === revision
  const [loadedName, setLoadedName] = useState<string>()
  const [data, setData] = useState<EntityRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm()
  const navigate = useNavigate()

  useEffect(() => {
    alive.current = true
    let active = true
    setLoadedName(name)
    setData(null)
    setLoading(true)
    setSaving(false)
    form.resetFields()
    if (name) {
      profileApi
        .get(name)
        .then((res) => {
          if (!active || !currentRoute()) return
          const d = res.data.data
          setData(d)
          form.setFieldsValue({
            type: d.type,
            conf: typeof d.conf === 'string' ? d.conf : JSON.stringify(d.conf, null, 2),
          })
        })
        .catch(() => {})
        .finally(() => {
          if (active && currentRoute()) setLoading(false)
        })
    } else setLoading(false)
    return () => {
      active = false
      alive.current = false
    }
  }, [name])

  const handleSave = async (values: FormValues) => {
    if (!name || !currentRoute() || loadedName !== name || loading || !data) return
    setSaving(true)
    try {
      await profileApi.update(name, {
        type: typeof values.type === 'string' ? values.type : undefined,
        conf: typeof values.conf === 'string' ? values.conf : undefined,
      })
      if (currentRoute()) message.success(t('Profile updated'))
    } catch (e: unknown) {
      if (currentRoute()) message.error(errorMessage(e, t('Update failed')))
    } finally {
      if (currentRoute()) setSaving(false)
    }
  }

  if (loading || loadedName !== name) return <Spin size="large" />
  if (!data) return <div>{t('Profile not found')}</div>

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/profile')}>
          {t('Back')}
        </Button>
      </Space>
      <Typography.Title level={4}>
        {t(can('PROFILE_UPDATE') ? 'Edit Profile:' : 'View public configuration')} {name}
      </Typography.Title>

      <Card>
        <Form
          form={form}
          layout="vertical"
          disabled={!can('PROFILE_UPDATE') || saving}
          onFinish={(values) =>
            authorize(t('Confirm shared resource change'), () => handleSave(values))
          }
        >
          <Form.Item name="type" label={t('Type')} rules={[{ required: true }]}>
            <Select>
              <Select.Option value="xijson">xijson</Select.Option>
              <Select.Option value="xijsonv1">{t('xijsonv1 (legacy)')}</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="conf" label={t('Configuration (JSON)')} rules={[{ required: true }]}>
            <Input.TextArea rows={25} style={{ fontFamily: 'monospace', fontSize: 12 }} />
          </Form.Item>
          {can('PROFILE_UPDATE') && (
            <Form.Item>
              <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving}>
                {t('Save Changes')}{' '}
              </Button>
            </Form.Item>
          )}
        </Form>
      </Card>
      {dialog}
    </div>
  )
}

export default ProfileEditor
