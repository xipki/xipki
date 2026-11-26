// License Apache License 2.0


import { useI18n } from '../../i18n'
import React, { useContext, useEffect, useState } from 'react'
import { Alert, Form, Input, Select, Upload, Button, Card, message, Typography, Tabs } from 'antd'
import type { UploadFile } from 'antd'
import { UploadOutlined, ArrowLeftOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { canIssueFromCa, certApi, saveDownload } from '../../api/cert'
import { caApi } from '../../api/ca'
import api from '../../api/client'
import { AuthContext, useCan } from '../../auth'
import { enrollmentOptions } from '../../access-policy'
import type { CaOption } from '../../ca-availability'

type EnrollmentValues = {
  ca: string
  profile: string
  subject: string
  csr: UploadFile[]
  targetCert: UploadFile[]
  notBefore?: string
  notAfter?: string
  downloadPassword: string
}
const fileEvent = (event: { fileList: UploadFile[] }) => event?.fileList

const CertEnroll: React.FC = () => {
  const { t } = useI18n()
  const can = useCan()
  const user = useContext(AuthContext)
  const utcRule = {
    pattern: /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/,
    message: t('Use ISO-8601 UTC, e.g. 2026-10-23T00:00:00Z'),
  }
  const [cas, setCas] = useState<CaOption[]>([])
  const [profiles, setProfiles] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState('')
  const [issued, setIssued] = useState<{ ca: string; serial: string }>()
  const [form] = Form.useForm<EnrollmentValues>()
  const selectedCa = Form.useWatch('ca', form)
  const navigate = useNavigate()

  useEffect(() => {
    caApi
      .list()
      .then((res) =>
        setCas(
          (res.data.data || []).filter(
            (ca: CaOption) =>
              can('CERT_ISSUE', ca) || can('CERT_KEYGEN', ca) || can('CERT_CROSS', ca),
          ),
        ),
      )
      .catch(() => {})
    return () => {
      form.resetFields()
    }
  }, [form])

  const loadProfiles = async (ca: string, permission: string) => {
    setProfiles([])
    form.setFieldValue('profile', undefined)
    try {
      const res = await api.get(`/api/profile/ca/${encodeURIComponent(ca)}`, {
        params: { operation: permission },
      })
      setProfiles(res.data.data || [])
    } catch {
      /* The common client reports the error. */
    }
  }

  const enroll = async (mode: string, values: EnrollmentValues) => {
    if (loading) return
    if (
      values.notBefore &&
      values.notAfter &&
      Date.parse(values.notBefore) >= Date.parse(values.notAfter)
    ) {
      message.error(t('Not Before must precede Not After'))
      return
    }
    setLoading(true)
    setResult('')
    setIssued(undefined)
    try {
      if (mode === 'keygen') {
        const { ca, profile, subject, notBefore, notAfter, downloadPassword } = values
        const response = await certApi.enrollKeyDownload({
          ca,
          profile,
          subject,
          notBefore,
          notAfter,
          downloadPassword,
        })
        saveDownload(response.data, 'key-certificate.p12')
        setIssued({ ca, serial: response.headers['x-certificate-serial'] })
        message.success(
          t('Password-protected PKCS#12 downloaded. Keep the file and password securely.'),
        )
      } else {
        const data = new FormData()
        data.append('ca', values.ca)
        data.append('profile', values.profile)
        data.append('csr', values.csr[0].originFileObj!)
        if (mode === 'cross') data.append('targetCert', values.targetCert[0].originFileObj!)
        if (values.notBefore) data.append('notBefore', values.notBefore)
        if (values.notAfter) data.append('notAfter', values.notAfter)
        const response = await (mode === 'cross' ? certApi.enrollCross(data) : certApi.enroll(data))
        setResult(response.data.data.certPem)
        message.success(t('Certificate issued'))
      }
    } catch {
      /* Do not replay issuance: the common client reports reconciliation guidance. */
    } finally {
      form.resetFields(['downloadPassword', 'csr', 'targetCert'])
      setLoading(false)
    }
  }

  const material = (name: string, label: string) => (
    <Form.Item
      name={name}
      label={label}
      valuePropName="fileList"
      getValueFromEvent={fileEvent}
      rules={[{ required: true, message: t('Select a PEM or DER file') }]}
    >
      <Upload
        beforeUpload={(file) => {
          if (file.size > 2 * 1024 * 1024) {
            message.error(t('Each file must be at most 2 MiB'))
            return Upload.LIST_IGNORE
          }
          return false
        }}
        maxCount={1}
      >
        <Button icon={<UploadOutlined />}>{t('Select PEM / DER')}</Button>
      </Upload>
    </Form.Item>
  )

  const content = (mode: string) => {
    const permission =
      mode === 'keygen' ? 'CERT_KEYGEN' : mode === 'cross' ? 'CERT_CROSS' : 'CERT_ISSUE'
    const options = enrollmentOptions(user, permission, cas, selectedCa, profiles)
    return (
      <Card>
        <Form form={form} layout="vertical" onFinish={(values) => enroll(mode, values)}>
          <Form.Item name="ca" label={t('Issuing CA')} rules={[{ required: true }]}>
            <Select
              onChange={(ca) => void loadProfiles(ca, permission)}
              options={options.cas.map((ca) => ({
                value: ca.name,
                label: canIssueFromCa(ca)
                  ? ca.name
                  : t('{name} (unavailable for issuance)', { name: ca.name }),
                disabled: !canIssueFromCa(ca),
              }))}
            />
          </Form.Item>
          <Form.Item name="profile" label={t('Certificate Profile')} rules={[{ required: true }]}>
            <Select options={options.profiles.map((value) => ({ value }))} />
          </Form.Item>
          {mode === 'keygen' ? (
            <>
              <Form.Item name="subject" label={t('Subject DN')} rules={[{ required: true }]}>
                <Input placeholder="CN=example.com,O=Example,C=US" />
              </Form.Item>
              <Alert
                type="info"
                showIcon
                message={t(
                  'The private key is delivered once in an encrypted PKCS#12. Closing or refreshing this page cannot recover it.',
                )}
                style={{ marginBottom: 16 }}
              />
              <Form.Item
                name="downloadPassword"
                label={t('Download protection password')}
                rules={[{ required: true }, { min: 12 }]}
              >
                <Input.Password autoComplete="new-password" />
              </Form.Item>
            </>
          ) : (
            <>
              {material('csr', t('CSR (PEM / DER)'))}
              {mode === 'cross' &&
                material(
                  'targetCert',
                  t('Target CA certificate (same subject and public key as CSR)'),
                )}
            </>
          )}
          <Form.Item name="notBefore" label={t('Not Before (optional UTC)')} rules={[utcRule]}>
            <Input placeholder="2026-10-23T00:00:00Z" />
          </Form.Item>
          <Form.Item name="notAfter" label={t('Not After (optional UTC)')} rules={[utcRule]}>
            <Input placeholder="2027-10-23T00:00:00Z" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>
            {mode === 'keygen' ? t('Issue and download PKCS#12') : t('Issue certificate')}
          </Button>
        </Form>
      </Card>
    )
  }

  return (
    <div>
      <Button
        icon={<ArrowLeftOutlined />}
        onClick={() => navigate('/cert')}
        style={{ marginBottom: 16 }}
      >
        {t('Back')}
      </Button>
      <Typography.Title level={4}>{t('Enroll Certificate')}</Typography.Title>
      <Tabs
        destroyInactiveTabPane
        onChange={() => {
          form.resetFields()
          setResult('')
          setProfiles([])
        }}
        items={[
          ...(can('CERT_ISSUE')
            ? [{ key: 'csr', label: t('CSR Enrollment'), children: content('csr') }]
            : []),
          ...(can('CERT_KEYGEN')
            ? [{ key: 'keygen', label: t('Generate Key + Cert'), children: content('keygen') }]
            : []),
          ...(can('CERT_CROSS')
            ? [{ key: 'cross', label: t('Cross Certificate'), children: content('cross') }]
            : []),
        ]}
      />
      {result && (
        <Card title={t('Issued certificate')} style={{ marginTop: 16 }}>
          <Button
            onClick={() =>
              saveDownload(
                new Blob([result], { type: 'application/x-pem-file' }),
                'certificate.pem',
              )
            }
          >
            {t('Download public certificate')}
          </Button>
          <Input.TextArea
            value={result}
            rows={10}
            readOnly
            style={{ marginTop: 8, fontFamily: 'monospace' }}
          />
        </Card>
      )}
      {issued?.serial && (
        <Card style={{ marginTop: 16 }}>
          <a href={certApi.downloadUrl(issued.ca, issued.serial)} download>
            {t('Download public certificate')}
          </a>
        </Card>
      )}
    </div>
  )
}

export default CertEnroll
