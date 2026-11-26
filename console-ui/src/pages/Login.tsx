// License Apache License 2.0


import { useI18n } from '../i18n'
import React from 'react'
import { Form, Input, Button, Typography, message } from 'antd'
import { UserOutlined, LockOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import api from '../api/client'
import type { AuthUser } from '../auth'
import ApplicationHeader from '../components/ApplicationHeader'
import './Login.css'
import { errorMessage } from '../types/api'

interface Props {
  onSuccess: (user: AuthUser) => void
}

const Login: React.FC<Props> = ({ onSuccess }) => {
  const { t } = useI18n()
  const [loading, setLoading] = React.useState(false)
  const [certificateLoading, setCertificateLoading] = React.useState(false)
  const [methods, setMethods] = React.useState({ password: true, certificate: true })

  React.useEffect(() => {
    api
      .get<{ password: boolean; certificate: boolean }>('/api/auth/methods')
      .then((response) => setMethods(response.data))
      .catch(() => undefined)
  }, [])

  const onFinish = async (values: { username: string; password: string }) => {
    setLoading(true)
    try {
      const res = await api.post('/api/auth/login', values)
      if (res.data.success) {
        message.success(t('Login successful'))
        onSuccess(res.data.data)
      } else {
        message.error(res.data.error || t('Login failed'))
      }
    } catch (error: unknown) {
      if (
        typeof error === 'object' &&
        error &&
        'response' in error &&
        (error.response as { status?: number } | undefined)?.status === 401
      ) {
        message.error(t('Invalid credentials'))
      } else {
        message.error(errorMessage(error, t('Login failed')))
      }
    } finally {
      setLoading(false)
    }
  }

  const onCertificate = async () => {
    setCertificateLoading(true)
    try {
      const res = await api.post('/api/auth/certificate', {})
      message.success(t('Login successful'))
      onSuccess(res.data.data)
    } catch (error: unknown) {
      message.error(errorMessage(error, t('Client certificate login failed')))
    } finally {
      setCertificateLoading(false)
    }
  }

  return (
    <div className="login-page">
      <ApplicationHeader
        brand={
          <>
            <SafetyCertificateOutlined aria-hidden />
            {t('XiPKI Management')}
          </>
        }
      />
      <main className="login-main">
        <section className="login-introduction" aria-labelledby="login-product-title">
          <div className="login-introduction-content">
            <div className="login-product-icon" aria-hidden>
              <SafetyCertificateOutlined />
            </div>
            <Typography.Title id="login-product-title">{t('XiPKI CA Management')}</Typography.Title>
            <Typography.Paragraph>
              {t('Manage certificate authorities and certificates in one place.')}
            </Typography.Paragraph>
          </div>
        </section>
        <section className="login-form-section" aria-labelledby="login-form-title">
          <div className="login-form-content">
            <Typography.Title level={2} id="login-form-title">
              {t('Login')}
            </Typography.Title>
            <Typography.Paragraph className="login-form-description">
              {t('Use your platform account to continue.')}
            </Typography.Paragraph>
            {methods.password && (
              <Form onFinish={onFinish} size="large" layout="vertical" requiredMark={false}>
                <Form.Item
                  label={t('Username')}
                  name="username"
                  rules={[{ required: true, message: t('Please enter username') }]}
                >
                  <Input
                    prefix={<UserOutlined />}
                    autoComplete="username"
                    placeholder={t('Username')}
                  />
                </Form.Item>
                <Form.Item
                  label={t('Password')}
                  name="password"
                  rules={[{ required: true, message: t('Please enter password') }]}
                >
                  <Input.Password
                    prefix={<LockOutlined />}
                    autoComplete="current-password"
                    placeholder={t('Password')}
                  />
                </Form.Item>
                <Form.Item>
                  <Button type="primary" htmlType="submit" block loading={loading}>
                    {t('Login')}
                  </Button>
                </Form.Item>
              </Form>
            )}
            {methods.certificate && (
              <Button
                className="certificate-login"
                icon={<SafetyCertificateOutlined />}
                block
                size="large"
                loading={certificateLoading}
                onClick={onCertificate}
              >
                {t('Login with client certificate')}
              </Button>
            )}
          </div>
        </section>
      </main>
    </div>
  )
}

export default Login
