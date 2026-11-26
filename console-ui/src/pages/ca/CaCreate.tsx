// License Apache License 2.0


import { useI18n } from '../../i18n'
import { useEffect, useState } from 'react'
import {
  Alert,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Tabs,
  Checkbox,
  Button,
  Descriptions,
  message,
} from 'antd'
import { caApi } from '../../api/ca'
import CaConfigFields, { configValues, configuration } from './CaConfigFields'
import CaKeyFields, { readMaterial } from './CaKeyFields'
import { useCan } from '../../auth'
import { useReauthentication } from '../../components/Reauthentication'
import CaEnrollmentPage from './CaEnrollmentPage'
import {
  errorMessage,
  isFormValidationError,
  isHandledRequestError,
  type FormValues,
} from '../../types/api'

type CaCreateValues = FormValues & {
  name: string
  key: FormValues
  config?: FormValues
  nextCrlNo?: number
  subject?: string
  profile?: string
  serialNumber?: string
  notBefore?: string
  notAfter?: string
  certificate?: string
  certificateChain?: string[]
  acceptUnknownRevocation?: boolean
}

export default function CaCreate({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (name: string) => void
}) {
  const { t } = useI18n()
  const can = useCan()
  const { authorize, dialog } = useReauthentication()
  const [form] = Form.useForm()
  const [kind, setKind] = useState(
    can('CA_CREATE_ROOT') ? 'root' : can('CA_IMPORT') ? 'import' : 'intermediate',
  )
  const [intermediateVisited, setIntermediateVisited] = useState(
    !can('CA_CREATE_ROOT') && !can('CA_IMPORT'),
  )
  const [profiles, setProfiles] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [preview, setPreview] = useState<{
    valid: boolean
    diagnostic: string
    subject?: string
    issuer?: string
    certificateFingerprint?: string
    revocationCheck?: string
  }>()
  useEffect(() => {
    if (can('CA_CREATE_ROOT'))
      void caApi
        .options()
        .then((r) => setProfiles(r.data.data.profiles))
        .catch(() => {})
  }, [])
  async function submit() {
    try {
      const values: CaCreateValues = await form.validateFields()
      setBusy(true)
      const common = {
        name: values.name,
        key: values.key,
        config: configuration(values),
        nextCrlNo: values.nextCrlNo,
      }
      const response =
        kind === 'root'
          ? await caApi.createRoot({
              ...common,
              subject: values.subject,
              profile: values.profile,
              serialNumber: values.serialNumber || undefined,
              notBefore: values.notBefore || undefined,
              notAfter: values.notAfter || undefined,
            })
          : await caApi.create({
              ...common,
              certificate: values.certificate,
              certificateChain: values.certificateChain,
              acceptUnknownRevocation: values.acceptUnknownRevocation,
            })
      message.success(t('CA saved. Configure associations and activate when ready.'))
      form.resetFields()
      onCreated(response.data.data.name)
    } catch (error: unknown) {
      if (!isFormValidationError(error) && !isHandledRequestError(error))
        message.error(errorMessage(error, t('Operation failed')))
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <Modal
        open
        width={kind === 'intermediate' ? 960 : 760}
        title={t('Add CA')}
        okText={kind === 'root' ? t('Create root CA') : t('Import CA')}
        confirmLoading={busy}
        okButtonProps={{ disabled: kind === 'import' && preview && !preview.valid }}
        {...(kind === 'intermediate' ? { footer: null } : {})}
        cancelButtonProps={{ disabled: busy }}
        closable={!busy}
        maskClosable={false}
        onOk={() => {
          void form
            .validateFields()
            .then(() => authorize(t('Add CA'), submit))
            .catch(() => {})
        }}
        onCancel={() => {
          form.resetFields()
          onClose()
        }}
        destroyOnClose
      >
        <Tabs
          activeKey={kind}
          onChange={(key) => {
            setKind(key)
            if (key === 'intermediate') setIntermediateVisited(true)
            else {
              form.resetFields()
              form.setFieldValue('key', {
                mode: key === 'root' ? 'generate' : 'pkcs12',
                algorithm: 'RSA3072',
              })
            }
          }}
          items={[
            ...(can('CA_CREATE_ROOT')
              ? [{ key: 'root', label: t('Create root CA'), disabled: busy }]
              : []),
            ...(can('CA_IMPORT') || can('CA_ISSUE_SUBCA')
              ? [{ key: 'intermediate', label: t('Intermediate CA'), disabled: busy }]
              : []),
            ...(can('CA_IMPORT')
              ? [{ key: 'import', label: t('Import existing CA'), disabled: busy }]
              : []),
          ]}
        />
        {intermediateVisited && (
          <div style={{ display: kind === 'intermediate' ? 'block' : 'none' }}>
            <CaEnrollmentPage createOnly onCreated={onCreated} />
          </div>
        )}
        <div style={{ display: kind === 'intermediate' ? 'none' : 'block' }}>
          <Alert
            type="info"
            showIcon
            message={t(
              'New CAs default to inactive. After creation, bind profiles/requestors/publishers and explicitly activate. Signing materials are sent to the CA and are never returned by this form.',
            )}
            style={{ marginBottom: 16 }}
          />
          <Form
            name="ca-create"
            form={form}
            layout="vertical"
            disabled={busy}
            preserve={false}
            initialValues={{
              ...configValues(),
              nextCrlNo: 1,
              key: { mode: kind === 'root' ? 'generate' : 'pkcs12', algorithm: 'RSA3072' },
            }}
          >
            <Form.Item
              name="name"
              label={t('CA name')}
              rules={[
                { required: true },
                {
                  pattern: /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/,
                  message: t('Letters, numbers, dot, dash or underscore'),
                },
              ]}
            >
              <Input />
            </Form.Item>
            {kind === 'root' ? (
              <>
                <Form.Item name="subject" label={t('Subject')} rules={[{ required: true }]}>
                  <Input placeholder="CN=Example Root CA,O=Example,C=CN" />
                </Form.Item>
                <Form.Item
                  name="profile"
                  label={t('Root certificate profile')}
                  rules={[{ required: true }]}
                >
                  <Select options={profiles.map((value) => ({ value }))} />
                </Form.Item>
                <Form.Item name="serialNumber" label={t('Root serial number (optional)')}>
                  <Input placeholder={t('Decimal, 0x hex or RANDOM:20')} />
                </Form.Item>
                <Form.Item name="notBefore" label={t('Not before (optional UTC)')}>
                  <Input placeholder="2026-10-23T00:00:00Z" />
                </Form.Item>
                <Form.Item name="notAfter" label={t('Not after (optional UTC)')}>
                  <Input placeholder="2036-10-23T00:00:00Z" />
                </Form.Item>
              </>
            ) : (
              <>
                <Form.Item label={t('CA certificate (PEM/DER, max 2 MiB)')} required>
                  <input
                    type="file"
                    aria-label={t('CA certificate')}
                    accept=".pem,.der,.crt,.cer"
                    onChange={(event) => {
                      const file = event.target.files?.[0]
                      setPreview(undefined)
                      if (file)
                        void readMaterial(file)
                          .then((value) => form.setFieldValue('certificate', value))
                          .catch((e) => message.error(t(e.message)))
                    }}
                  />
                </Form.Item>
                <Form.Item name="certificate" hidden rules={[{ required: true }]}>
                  <Input />
                </Form.Item>
                <Form.Item label={t('Issuer chain (required for non-root CA; PEM/DER)')}>
                  <input
                    type="file"
                    multiple
                    aria-label={t('CA certificate chain')}
                    onChange={(event) => {
                      setPreview(undefined)
                      void Promise.all(Array.from(event.target.files || []).map(readMaterial))
                        .then((value) => form.setFieldValue('certificateChain', value))
                        .catch((e) => message.error(t(e.message)))
                    }}
                  />
                </Form.Item>
                <Form.Item name="certificateChain" hidden>
                  <Input />
                </Form.Item>
                <Button
                  style={{ marginBottom: 16 }}
                  onClick={() =>
                    void form
                      .validateFields(['certificate'])
                      .then(() =>
                        authorize(t('Validate certificate chain'), async () => {
                          const r = await caApi.preflight({
                            certificate: form.getFieldValue('certificate'),
                            certificateChain: form.getFieldValue('certificateChain'),
                          })
                          setPreview(r.data.data)
                        }),
                      )
                      .catch(() => {})
                  }
                >
                  {t('Validate certificate chain')}
                </Button>
                {preview && (
                  <>
                    <Alert
                      type={preview.valid ? 'success' : 'error'}
                      showIcon
                      message={
                        preview.valid ? t('Certificate chain verified') : t(preview.diagnostic)
                      }
                      style={{ marginBottom: 16 }}
                    />
                    <Descriptions column={1} bordered size="small" style={{ marginBottom: 16 }}>
                      <Descriptions.Item label={t('Subject')}>{preview.subject}</Descriptions.Item>
                      <Descriptions.Item label={t('Issuer')}>{preview.issuer}</Descriptions.Item>
                      <Descriptions.Item label={t('Certificate fingerprint')}>
                        <span style={{ wordBreak: 'break-all' }}>
                          {preview.certificateFingerprint}
                        </span>
                      </Descriptions.Item>
                      <Descriptions.Item label={t('Revocation check')}>
                        {t(preview.revocationCheck || 'unknown')}
                      </Descriptions.Item>
                    </Descriptions>
                  </>
                )}
                <Form.Item name="acceptUnknownRevocation" valuePropName="checked">
                  <Checkbox>
                    {t(
                      'I accept that external revocation status cannot be verified. Known local revocations are still rejected.',
                    )}
                  </Checkbox>
                </Form.Item>
              </>
            )}
            <CaKeyFields allowGenerate={kind === 'root'} />
            <CaConfigFields />
            <Form.Item name="nextCrlNo" label={t('Initial next CRL number')}>
              <InputNumber min={1} />
            </Form.Item>
          </Form>
        </div>
      </Modal>
      {dialog}
    </>
  )
}
