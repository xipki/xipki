// License Apache License 2.0


import { useEffect, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Form,
  Input,
  Select,
  Space,
  Steps,
  Table,
  Tag,
  message,
} from 'antd'
import { useI18n } from '../../i18n'
import { useCan } from '../../auth'
import { useReauthentication } from '../../components/Reauthentication'
import { caEnrollmentApi, type CaEnrollment } from '../../api/ca'
import CaKeyFields, { readMaterial } from './CaKeyFields'
import { enrollmentActions, newIdempotencyKey, publicPem } from './enrollment-policy'
import type { CaEnrollmentParent, FormValues } from '../../types/api'

function download(value: string, filename: string, label: string) {
  const url = URL.createObjectURL(
    new Blob([publicPem(value, label)], { type: 'application/x-pem-file' }),
  )
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default function CaEnrollmentPage({
  createOnly = false,
  onCreated,
}: {
  createOnly?: boolean
  onCreated?: (name: string) => void
}) {
  const { t } = useI18n(),
    can = useCan(),
    { authorize, dialog } = useReauthentication()
  const [form] = Form.useForm(),
    [responseForm] = Form.useForm()
  const [parents, setParents] = useState<CaEnrollmentParent[]>([]),
    [operations, setOperations] = useState<CaEnrollment[]>([])
  const [selected, setSelected] = useState<CaEnrollment>(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(false)
  const [confirmRegistration, setConfirmRegistration] = useState(false)
  const idempotency = useRef(newIdempotencyKey())
  const purpose = Form.useWatch('purpose', form) || (can('CA_IMPORT') ? 'REGISTER_CA' : 'SIGN_ONLY')
  const mode = Form.useWatch('mode', form) || 'ONLINE',
    parent = Form.useWatch('parentCa', form),
    keyMode = Form.useWatch(['key', 'mode'], form)
  const refresh = async () => {
    try {
      const r = await caEnrollmentApi.list()
      setOperations(r.data.data)
      setError(false)
    } catch {
      setError(true)
    }
  }
  useEffect(() => {
    void caEnrollmentApi
      .options()
      .then((r) => setParents(r.data.data))
      .catch(() => setError(true))
    if (!createOnly) void refresh()
  }, [])
  const update = (op: CaEnrollment) => {
    setSelected(op)
    setOperations((old) => [op, ...old.filter((item) => item.operationId !== op.operationId)])
  }
  async function prepare() {
    const values: FormValues = await form.validateFields()
    authorize(t('Prepare intermediate CA'), async () => {
      setBusy(true)
      try {
        const body: FormValues = { ...values, idempotencyKey: idempotency.current }
        if (values.mode === 'EXTERNAL') {
          delete body.parentCa
          delete body.profile
        }
        if (values.purpose === 'SIGN_ONLY') {
          delete body.name
          delete body.key
          delete body.subject
          body.mode = 'ONLINE'
        }
        const key =
          values.key && typeof values.key === 'object' ? (values.key as FormValues) : undefined
        if (key?.mode !== 'pkcs11' && values.purpose === 'REGISTER_CA' && !values.useExternalCsr)
          delete body.csr
        delete body.useExternalCsr
        const r = await caEnrollmentApi.prepare(body)
        update(r.data.data)
        form.resetFields()
        idempotency.current = newIdempotencyKey()
      } catch {
        /* Shared client reports the error; reuse idempotency key if the response was lost. */
      } finally {
        setBusy(false)
      }
    })
  }
  function act(action: string) {
    if (!selected || busy) return
    void (async () => {
      const extra = action === 'certificate' ? await responseForm.validateFields() : {}
      authorize(t('Continue CA enrollment'), async () => {
        setBusy(true)
        try {
          const r = await caEnrollmentApi.action(selected, action, {
            ...extra,
            ...(action === 'reconcile'
              ? { confirmRegistrationNotCompleted: confirmRegistration }
              : {}),
          })
          update(r.data.data)
          responseForm.resetFields()
          setConfirmRegistration(false)
          if (r.data.data.status === 'REGISTERED') {
            message.success(t('CA saved. Configure associations and activate when ready.'))
            if (r.data.data.data.name) onCreated?.(r.data.data.data.name)
          }
        } finally {
          setBusy(false)
        }
      })
    })().catch(() => {})
  }
  const actionLabels: Record<string, string> = {
    issue: t('Issue intermediate certificate'),
    register: t('Register inactive CA'),
    reconcile: t('Reconcile result'),
    certificate: t('Accept certificate response'),
    cancel: t('Cancel enrollment'),
  }
  const actions = selected ? enrollmentActions(selected.status, selected.purpose) : []
  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        message={t('Intermediate CA workflow')}
        description={t(
          'Prepare a CSR, obtain its CA certificate, then register it inactive. Parent relationships come from the verified certificate chain.',
        )}
      />
      {createOnly && !selected && (
        <Form
          name="ca-enrollment"
          form={form}
          layout="vertical"
          disabled={busy}
          preserve
          initialValues={{
            purpose: can('CA_IMPORT') ? 'REGISTER_CA' : 'SIGN_ONLY',
            mode: can('CA_ISSUE_SUBCA') ? 'ONLINE' : 'EXTERNAL',
            key: { mode: 'generate', algorithm: 'RSA3072' },
          }}
        >
          <Form.Item name="purpose" label={t('Enrollment purpose')} rules={[{ required: true }]}>
            <Select
              onChange={(value) => {
                if (value === 'SIGN_ONLY') form.setFieldValue('mode', 'ONLINE')
              }}
              options={[
                ...(can('CA_IMPORT')
                  ? [{ value: 'REGISTER_CA', label: t('Manage this CA in XiPKI') }]
                  : []),
                ...(can('CA_ISSUE_SUBCA')
                  ? [{ value: 'SIGN_ONLY', label: t('Sign an external CSR only') }]
                  : []),
              ]}
            />
          </Form.Item>
          {purpose === 'REGISTER_CA' && (
            <>
              <Form.Item
                name="name"
                label={t('CA name')}
                rules={[{ required: true }, { pattern: /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/ }]}
              >
                <Input />
              </Form.Item>
              <Form.Item name="mode" label={t('Certificate issuer')} rules={[{ required: true }]}>
                <Select
                  options={[
                    ...(can('CA_ISSUE_SUBCA')
                      ? [{ value: 'ONLINE', label: t('Online parent in this system') }]
                      : []),
                    { value: 'EXTERNAL', label: t('External or offline parent') },
                  ]}
                />
              </Form.Item>
            </>
          )}
          {mode === 'ONLINE' && (
            <>
              <Form.Item name="parentCa" label={t('Parent CA')} rules={[{ required: true }]}>
                <Select
                  onChange={() => form.setFieldValue('profile', undefined)}
                  options={parents.map((p) => ({ value: p.name, label: p.name }))}
                />
              </Form.Item>
              <Form.Item
                name="profile"
                label={t('SubCA certificate profile')}
                rules={[{ required: true }]}
              >
                <Select
                  options={(parents.find((p) => p.name === parent)?.profiles || []).map((p) => ({
                    value: p.name,
                    label: `${p.name} (pathLen: ${p.capabilities?.pathLenConstraint ?? '∞'})`,
                  }))}
                />
              </Form.Item>
              {!parents.length && (
                <Alert
                  type="warning"
                  showIcon
                  message={t(
                    'No permitted parent and SubCA profile. Bind a SubCA profile to the parent and grant CA_ISSUE_SUBCA for that CA and profile.',
                  )}
                />
              )}
            </>
          )}
          {purpose === 'REGISTER_CA' && (
            <>
              <Alert
                type="warning"
                showIcon
                message={t(
                  'Hosted software keys require the persistent encrypted key volume and encryption secret. HSM keys require an externally generated CSR; no PIN is accepted.',
                )}
                style={{ marginBottom: 16 }}
              />
              <CaKeyFields allowGenerate />
              {keyMode !== 'pkcs11' && (
                <Form.Item name="subject" label={t('Subject')} rules={[{ required: true }]}>
                  <Input placeholder="CN=Example Issuing CA,O=Example,C=CN" />
                </Form.Item>
              )}
            </>
          )}
          {(purpose === 'SIGN_ONLY' || keyMode === 'pkcs11') && (
            <>
              <Form.Item label={t('CSR file')} required>
                <input
                  type="file"
                  accept=".csr,.pem,.der"
                  aria-label={t('CSR file')}
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file)
                      void readMaterial(file)
                        .then((value) => form.setFieldValue('csr', value))
                        .catch((error) => message.error(t(error.message)))
                  }}
                />
              </Form.Item>
              <Form.Item name="csr" hidden rules={[{ required: true }]}>
                <Input />
              </Form.Item>
            </>
          )}
          {mode === 'ONLINE' && (
            <>
              <Form.Item name="notBefore" label={t('Not before (optional UTC)')}>
                <Input placeholder="2026-10-27T00:00:00Z" />
              </Form.Item>
              <Form.Item name="notAfter" label={t('Not after (optional UTC)')}>
                <Input placeholder="2030-10-27T00:00:00Z" />
              </Form.Item>
            </>
          )}
          <Button type="primary" loading={busy} onClick={() => void prepare().catch(() => {})}>
            {t('Prepare intermediate CA')}
          </Button>
        </Form>
      )}
      {error && (
        <Alert
          type="error"
          message={t('Unable to load CA enrollments')}
          action={<Button onClick={() => void refresh()}>{t('Retry')}</Button>}
        />
      )}
      {!createOnly && (
        <>
          <Button disabled={busy} onClick={() => void refresh()}>
            {t('Refresh')}
          </Button>
          <Table
            size="small"
            rowKey="operationId"
            dataSource={operations}
            pagination={{ pageSize: 10 }}
            columns={[
              {
                title: t('CA name'),
                render: (_value: unknown, op: CaEnrollment) =>
                  op.data.name || t('Sign an external CSR only'),
              },
              {
                title: t('Parent CA'),
                render: (_value: unknown, op: CaEnrollment) =>
                  op.data.parentCa || t('External or offline parent'),
              },
              {
                title: t('Status'),
                dataIndex: 'status',
                render: (value: string) => <Tag>{t(value)}</Tag>,
              },
              {
                title: t('Actions'),
                render: (_value: unknown, op: CaEnrollment) => (
                  <Button
                    disabled={busy}
                    onClick={() => {
                      setSelected(op)
                      responseForm.resetFields()
                    }}
                  >
                    {t('Detail')}
                  </Button>
                ),
              },
            ]}
          />
        </>
      )}
      {selected && (
        <Card
          title={t('CA enrollment')}
          extra={
            <Button disabled={busy} onClick={() => setSelected(undefined)}>
              {t('Back')}
            </Button>
          }
        >
          <Steps
            size="small"
            current={selected.status === 'REGISTERED' ? 3 : selected.data.certificate ? 2 : 1}
            items={[
              { title: t('Prepare') },
              { title: t('Obtain certificate') },
              { title: t('Register inactive CA') },
              { title: t('Configure and activate') },
            ]}
            style={{ marginBottom: 24 }}
          />
          <Descriptions bordered size="small" column={1}>
            <Descriptions.Item label={t('Operation ID')}>{selected.operationId}</Descriptions.Item>
            <Descriptions.Item label={t('Status')}>
              <Tag>{t(selected.status)}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label={t('CA name')}>
              {selected.data.name || t('Sign an external CSR only')}
            </Descriptions.Item>
            <Descriptions.Item label={t('Parent CA')}>
              {selected.data.parentCa || t('External or offline parent')}
            </Descriptions.Item>
            <Descriptions.Item label={t('Parent certificate fingerprint')}>
              <TypographyText value={selected.data.parentFingerprint} />
            </Descriptions.Item>
            <Descriptions.Item label={t('CSR public key fingerprint')}>
              <TypographyText value={selected.data.subjectKeyFingerprint} />
            </Descriptions.Item>
            {selected.data.certificate && (
              <>
                <Descriptions.Item label={t('Subject')}>
                  {selected.data.issuedSubject}
                </Descriptions.Item>
                <Descriptions.Item label={t('Issuer')}>
                  {selected.data.issuedIssuer}
                </Descriptions.Item>
                <Descriptions.Item label={t('Not Before')}>
                  {selected.data.issuedNotBefore}
                </Descriptions.Item>
                <Descriptions.Item label={t('Not After')}>
                  {selected.data.issuedNotAfter}
                </Descriptions.Item>
                <Descriptions.Item label={t('CA path length')}>
                  {selected.data.issuedPathLength === 2147483647
                    ? '∞'
                    : selected.data.issuedPathLength}
                </Descriptions.Item>
              </>
            )}
          </Descriptions>
          {selected.data.diagnostic && (
            <Alert
              style={{ marginTop: 16 }}
              type="warning"
              showIcon
              message={t(selected.data.diagnostic)}
            />
          )}
          {selected.status === 'RESULT_UNKNOWN' && selected.data.stage === 'REGISTER' && (
            <Checkbox
              checked={confirmRegistration}
              onChange={(e) => setConfirmRegistration(e.target.checked)}
              style={{ marginTop: 16 }}
            >
              {t(
                'I verified in the CA engine that registration has finished unsuccessfully and no request is still running. Allow registration retry with the existing certificate.',
              )}
            </Checkbox>
          )}
          <Space wrap style={{ margin: '16px 0' }}>
            <Button
              onClick={() => download(selected.data.csr, 'ca-request.csr', 'CERTIFICATE REQUEST')}
            >
              {t('Download CSR')}
            </Button>
            {selected.data.certificate && (
              <Button
                onClick={() =>
                  download(selected.data.certificate!, 'ca-certificate.pem', 'CERTIFICATE')
                }
              >
                {t('Download certificate')}
              </Button>
            )}
          </Space>
          {actions.includes('certificate') && (
            <Form form={responseForm} layout="vertical" disabled={busy}>
              <Form.Item
                name="certificate"
                label={t('CA certificate')}
                rules={[{ required: true }]}
              >
                <Input.TextArea rows={4} placeholder="-----BEGIN CERTIFICATE-----" />
              </Form.Item>
              <Form.Item label={t('Complete issuer chain to the self-signed root')} required>
                <input
                  type="file"
                  multiple
                  accept=".pem,.der,.crt,.cer"
                  aria-label={t('CA certificate chain')}
                  onChange={(e) => {
                    void Promise.all(Array.from(e.target.files || []).map(readMaterial))
                      .then((value) => responseForm.setFieldValue('certificateChain', value))
                      .catch((error) => message.error(t(error.message)))
                  }}
                />
              </Form.Item>
              <Form.Item name="certificateChain" hidden rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              <Form.Item
                name="acceptUnknownRevocation"
                valuePropName="checked"
                rules={[
                  { validator: (_, value) => (value ? Promise.resolve() : Promise.reject()) },
                ]}
              >
                <Checkbox>
                  {t(
                    'I accept that external revocation status cannot be verified. Known local revocations are still rejected.',
                  )}
                </Checkbox>
              </Form.Item>
            </Form>
          )}
          <Space wrap>
            {actions.map((action) => (
              <Button
                key={action}
                danger={action === 'cancel'}
                type={action === 'issue' || action === 'register' ? 'primary' : 'default'}
                loading={busy}
                onClick={() => act(action)}
              >
                {actionLabels[action]}
              </Button>
            ))}
          </Space>
        </Card>
      )}
      {dialog}
    </Space>
  )
}

function TypographyText({ value }: { value?: string }) {
  return <span style={{ overflowWrap: 'anywhere', fontFamily: 'monospace' }}>{value || '—'}</span>
}
