// License Apache License 2.0


import { useContext, useState } from 'react'
import {
  Avatar,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  Modal,
  Space,
  Tag,
  Typography,
  message,
} from 'antd'
import { EditOutlined, LockOutlined, UserOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { AuthContext } from '../../auth'
import { useI18n } from '../../i18n'
import api from '../../api/client'
import './MyAccount.css'

export default function MyAccount({
  onDisplayNameSaved,
}: {
  onDisplayNameSaved: (displayName: string | null) => void
}) {
  const user = useContext(AuthContext)
  const { t } = useI18n()
  const navigate = useNavigate()
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm<{ displayName: string }>()
  const save = async ({ displayName }: { displayName?: string }) => {
    if (busy) return
    setBusy(true)
    try {
      const { data } = await api.put<{ data: { displayName: string | null } }>(
        '/api/auth/profile',
        { displayName: displayName || null },
      )
      onDisplayNameSaved(data.data.displayName)
      setEditing(false)
      message.success(t('Display name updated.'))
    } catch {
      /* The shared client reports errors; keep the draft available for retry. */
    } finally {
      setBusy(false)
    }
  }
  if (!user) return null
  return (
    <div className="my-account">
      <Typography.Title level={3}>{t('My account')}</Typography.Title>
      <Typography.Paragraph type="secondary">
        {t('Your profile and assigned roles.')}
      </Typography.Paragraph>
      <div className="my-account-grid">
        <Card
          title={t('Account information')}
          extra={
            <Button
              icon={<EditOutlined />}
              onClick={() => {
                form.setFieldsValue({ displayName: user.displayName || '' })
                setEditing(true)
              }}
            >
              {t('Edit')}
            </Button>
          }
        >
          <div className="my-account-identity">
            <Avatar size={56} icon={<UserOutlined />} />
            <div>
              <Typography.Title level={4}>{user.displayName || user.username}</Typography.Title>
              <Typography.Text type="secondary">{user.username}</Typography.Text>
            </div>
          </div>
          <Descriptions
            column={1}
            items={[
              { key: 'username', label: t('Username'), children: user.username },
              {
                key: 'displayName',
                label: t('Display name'),
                children: user.displayName || t('None'),
              },
              {
                key: 'roles',
                label: t('Assigned roles'),
                children: user.roles.length ? (
                  <Space wrap>
                    {user.roles.map((role) => (
                      <Tag key={role}>{role}</Tag>
                    ))}
                  </Space>
                ) : (
                  t('None')
                ),
              },
            ]}
          />
          <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
            {t('Contact a super administrator to obtain role and resource grants.')}
          </Typography.Paragraph>
        </Card>
        <Card
          title={
            <Space>
              <LockOutlined />
              {t('Account security')}
            </Space>
          }
        >
          <Typography.Title level={5}>{t('Change password')}</Typography.Title>
          <Typography.Paragraph type="secondary">
            {t(
              'Changing your password ends the current session. Sign in again with the new password.',
            )}
          </Typography.Paragraph>
          <Button icon={<LockOutlined />} onClick={() => navigate('/account/password')}>
            {t('Change password')}
          </Button>
        </Card>
      </div>
      <Modal
        title={t('Edit display name')}
        open={editing}
        onCancel={() => {
          if (!busy) setEditing(false)
        }}
        onOk={() => form.submit()}
        okText={t('Save')}
        cancelText={t('Cancel')}
        confirmLoading={busy}
        cancelButtonProps={{ disabled: busy }}
        closable={!busy}
        maskClosable={!busy}
        keyboard={!busy}
      >
        <Form form={form} layout="vertical" onFinish={save} disabled={busy}>
          <Form.Item
            name="displayName"
            label={t('Display name')}
            extra={t('Leave blank to use your username.')}
            rules={[
              {
                validator: (_, value?: string) => {
                  if (
                    !value ||
                    (value.length <= 128 && !/[\u0000-\u001f\u007f-\u009f]/.test(value))
                  )
                    return Promise.resolve()
                  return Promise.reject(
                    new Error(t('Use at most 128 characters without control characters.')),
                  )
                },
              },
            ]}
          >
            <Input
              maxLength={128}
              showCount
              autoComplete="nickname"
              onPressEnter={(event) => {
                event.preventDefault()
                form.submit()
              }}
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
