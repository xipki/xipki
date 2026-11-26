// License Apache License 2.0


import { useContext, useState } from 'react'
import { Alert, Button, Card, Form, Input, message, Typography } from 'antd'
import { AuthContext } from '../../auth'
import api, { authenticationRequiredEvent } from '../../api/client'
import { useI18n } from '../../i18n'

export default function PasswordChange() {
  const { t } = useI18n()
  const user = useContext(AuthContext)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm()
  const submit = async (values: { currentPassword: string; newPassword: string }) => {
    if (busy) return
    setBusy(true)
    try {
      await api.post('/api/auth/password', {
        currentPassword: values.currentPassword,
        newPassword: values.newPassword,
      })
      form.resetFields()
      message.success(t('Password changed. Sign in again with your new password.'))
      window.dispatchEvent(new Event(authenticationRequiredEvent))
    } catch {
      /* Common client reports failures. */
    } finally {
      form.resetFields()
      setBusy(false)
    }
  }
  return (
    <Card style={{ maxWidth: 600, margin: '24px auto' }}>
      <Typography.Title level={3}>{t('Change password')}</Typography.Title>
      {user?.passwordChangeRequired && (
        <Alert
          type="warning"
          showIcon
          message={t('Change your temporary password before using the platform.')}
          style={{ marginBottom: 16 }}
        />
      )}
      <Typography.Paragraph>
        {t('Use at least 15 characters and at most 72 UTF-8 bytes. Spaces are allowed.')}
      </Typography.Paragraph>
      <Form form={form} layout="vertical" onFinish={submit}>
        <Form.Item
          name="currentPassword"
          label={t('Current password')}
          rules={[{ required: true }]}
        >
          <Input.Password autoComplete="current-password" />
        </Form.Item>
        <Form.Item
          name="newPassword"
          label={t('New password')}
          rules={[
            { required: true },
            {
              validator: (_, value: string) => {
                if (
                  !value ||
                  ([...value].length >= 15 &&
                    new TextEncoder().encode(value).length <= 72 &&
                    !/[\0\r\n]/.test(value))
                )
                  return Promise.resolve()
                return Promise.reject(
                  new Error(
                    t('Use at least 15 characters and at most 72 UTF-8 bytes. Spaces are allowed.'),
                  ),
                )
              },
            },
          ]}
        >
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Form.Item
          name="confirmPassword"
          label={t('Confirm new password')}
          dependencies={['newPassword']}
          rules={[
            { required: true },
            {
              validator: (_, value) =>
                value === form.getFieldValue('newPassword')
                  ? Promise.resolve()
                  : Promise.reject(new Error(t('Passwords do not match'))),
            },
          ]}
        >
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={busy}>
          {t('Change password')}
        </Button>
      </Form>
    </Card>
  )
}
