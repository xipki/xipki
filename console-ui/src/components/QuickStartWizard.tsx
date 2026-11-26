// License Apache License 2.0


import { useContext, useEffect, useState } from 'react'
import { RocketOutlined } from '@ant-design/icons'
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Form,
  Input,
  Modal,
  Progress,
  Space,
  Steps,
  Typography,
  message,
} from 'antd'
import { quickStartApi } from '../api/system'
import { AuthContext, useCan } from '../auth'
import { useI18n } from '../i18n'
import type { QuickStartRequest, QuickStartStatus } from '../types/api'
import { useReauthentication } from './Reauthentication'
import { quickStartDefaults, quickStartProgress, quickStartVisible } from './quick-start-model'

type Values = Omit<QuickStartRequest, 'confirmed'>

/** Guides the initial super administrator through one safe, resumable CA bootstrap. */
export default function QuickStartWizard() {
  const { t } = useI18n()
  const user = useContext(AuthContext)
  const can = useCan()
  const isSuperAdmin = user?.roles.includes('SUPER_ADMIN') === true
  const canCreateRoot = can('CA_CREATE_ROOT')
  const [status, setStatus] = useState<QuickStartStatus | null>(null)
  const [loading, setLoading] = useState(isSuperAdmin && canCreateRoot)
  const [open, setOpen] = useState(false)
  const [step, setStep] = useState(0)
  const [confirmed, setConfirmed] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [values, setValues] = useState<Values>(quickStartDefaults)
  const [form] = Form.useForm<Values>()
  const reauthentication = useReauthentication('quick-start')

  useEffect(() => {
    if (!isSuperAdmin || !canCreateRoot) return
    let active = true
    quickStartApi
      .status()
      .then((response) => {
        if (active) setStatus(response.data.data)
      })
      .catch(() => {})
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [isSuperAdmin, canCreateRoot])

  if (loading || !quickStartVisible(status, isSuperAdmin, canCreateRoot)) return null

  const progress = quickStartProgress(status!)
  const conflicting = status!.state === 'CONFLICT'

  /** Validates operator inputs before showing the irreversible action summary. */
  const review = async () => {
    const next = await form.validateFields()
    setValues(next)
    setStep(1)
  }

  /** Runs the idempotent server workflow only after explicit confirmation and reauthentication. */
  const execute = () => {
    if (!confirmed || submitting) return
    reauthentication.authorize(t('Confirm Quick Start'), async () => {
      setSubmitting(true)
      try {
        const response = await quickStartApi.execute({ ...values, confirmed: true })
        setStatus(response.data.data)
        setOpen(false)
        if (response.data.data.state === 'COMPLETED') {
          message.success(t('Quick Start completed'))
        } else {
          message.info(t('Quick Start progress saved. Resume setup to finish.'))
        }
      } catch (error) {
        // A remote timeout can happen after some idempotent steps committed. Re-read actual state
        // so the same screen offers Resume without guessing whether the write took effect.
        try {
          const response = await quickStartApi.status()
          setStatus(response.data.data)
        } finally {
          throw error
        }
      } finally {
        setSubmitting(false)
      }
    })
  }

  /** Resets transient review state while retaining server-observed progress. */
  const close = () => {
    if (submitting) return
    setOpen(false)
    setStep(0)
    setConfirmed(false)
  }

  return (
    <>
      <Card
        style={{ marginBottom: 24 }}
        title={
          <Space>
            <RocketOutlined />
            {t('Quick Start')}
          </Space>
        }
        extra={
          !conflicting && (
            <Button type="primary" onClick={() => setOpen(true)}>
              {status!.state === 'IN_PROGRESS' ? t('Resume setup') : t('Start setup')}
            </Button>
          )
        }
      >
        {conflicting ? (
          <Alert
            type="warning"
            showIcon
            message={t('Quick Start cannot continue')}
            description={t(
              'A reserved Quick Start resource already exists with different content. Existing resources were not changed.',
            )}
          />
        ) : (
          <Space direction="vertical" style={{ width: '100%' }} size="small">
            <Typography.Text>
              {t(
                'Create a software-backed root CA and ready-to-use TLS server and client profiles.',
              )}
            </Typography.Text>
            {status!.state === 'IN_PROGRESS' && (
              <Progress
                percent={
                  progress.total ? Math.round((progress.complete / progress.total) * 100) : 0
                }
                status="active"
              />
            )}
          </Space>
        )}
      </Card>

      <Modal
        title={t('XiPKI Quick Start')}
        open={open}
        onCancel={close}
        closable={!submitting}
        maskClosable={!submitting}
        footer={
          step === 0 ? (
            <Space>
              <Button onClick={close}>{t('Cancel')}</Button>
              <Button type="primary" onClick={() => void review()}>
                {t('Review')}
              </Button>
            </Space>
          ) : (
            <Space>
              <Button onClick={() => setStep(0)} disabled={submitting}>
                {t('Back')}
              </Button>
              <Button type="primary" onClick={execute} disabled={!confirmed} loading={submitting}>
                {t('Create and activate')}
              </Button>
            </Space>
          )
        }
      >
        <Steps
          current={step}
          size="small"
          items={[{ title: t('Identity') }, { title: t('Review and confirm') }]}
          style={{ marginBottom: 24 }}
        />
        {step === 0 ? (
          <Form form={form} layout="vertical" initialValues={quickStartDefaults}>
            <Form.Item
              name="caName"
              label={t('CA name')}
              rules={[
                { required: true },
                {
                  pattern: /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/,
                  message: t('Use letters, numbers, dot, underscore or hyphen.'),
                },
              ]}
            >
              <Input autoComplete="off" />
            </Form.Item>
            <Form.Item
              name="organization"
              label={t('Organization')}
              rules={[{ required: true, max: 128 }]}
            >
              <Input autoComplete="organization" />
            </Form.Item>
            <Form.Item
              name="country"
              label={t('Country code (optional)')}
              normalize={(value: string) => value?.trim().toUpperCase()}
              rules={[{ pattern: /^$|^[A-Z]{2}$/, message: t('Enter a two-letter country code.') }]}
            >
              <Input maxLength={2} placeholder="CN" autoComplete="country" />
            </Form.Item>
          </Form>
        ) : (
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <Descriptions bordered size="small" column={1}>
              <Descriptions.Item label={t('CA name')}>{values.caName}</Descriptions.Item>
              <Descriptions.Item label={t('Organization')}>{values.organization}</Descriptions.Item>
              <Descriptions.Item label={t('Country code')}>
                {values.country || t('Not set')}
              </Descriptions.Item>
              <Descriptions.Item label={t('Key algorithm')}>RSA 3072</Descriptions.Item>
              <Descriptions.Item label={t('Root CA validity')}>{t('10 years')}</Descriptions.Item>
              <Descriptions.Item label={t('Issued certificate maximum')}>
                397 {t('days')}
              </Descriptions.Item>
              <Descriptions.Item label={t('Certificate profiles')}>
                TLS Server, TLS Client
              </Descriptions.Item>
            </Descriptions>
            <Alert
              type="info"
              showIcon
              message={t('Existing resources are never overwritten or deleted.')}
            />
            <Checkbox checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)}>
              {t('I confirm creating and activating these resources.')}
            </Checkbox>
          </Space>
        )}
      </Modal>
      {reauthentication.dialog}
    </>
  )
}
