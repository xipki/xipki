// License Apache License 2.0


import { useI18n } from '../../i18n'
import { Form, Input, InputNumber, Select, Alert, message } from 'antd'

export async function readMaterial(file: File): Promise<string> {
  if (file.size > 2 * 1024 * 1024) throw new Error('Each file must be at most 2 MiB')
  const bytes = new Uint8Array(await file.arrayBuffer())
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}
export default function CaKeyFields({ allowGenerate = false }: { allowGenerate?: boolean }) {
  const { t } = useI18n()
  const form = Form.useFormInstance()
  const mode = Form.useWatch(['key', 'mode'], form)
  return (
    <>
      <Form.Item name={['key', 'mode']} label={t('Signing key')} rules={[{ required: true }]}>
        <Select
          onChange={(mode) => form.setFieldValue('key', { mode, algorithm: 'RSA3072' })}
          options={[
            ...(allowGenerate ? [{ value: 'generate', label: t('Generate software key') }] : []),
            { value: 'pkcs12', label: t('Upload PKCS#12') },
            { value: 'pkcs11', label: t('Existing CA PKCS#11 key') },
          ]}
        />
      </Form.Item>
      {mode === 'generate' && (
        <Form.Item name={['key', 'algorithm']} label={t('Key algorithm')}>
          <Select
            options={['RSA2048', 'RSA3072', 'RSA4096', 'EC_P256', 'EC_P384'].map((value) => ({
              value,
            }))}
          />
        </Form.Item>
      )}
      {mode === 'pkcs12' && (
        <>
          <Form.Item label={t('PKCS#12 file (max 2 MiB)')} required>
            <input
              type="file"
              accept=".p12,.pfx"
              aria-label={t('PKCS12 file')}
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file)
                  void readMaterial(file)
                    .then((value) => form.setFieldValue(['key', 'pkcs12'], value))
                    .catch((e) => message.error(t(e.message)))
              }}
            />
          </Form.Item>
          <Form.Item
            name={['key', 'pkcs12']}
            hidden
            rules={[{ required: true, message: t('Upload a PKCS#12 file') }]}
          >
            <Input />
          </Form.Item>
          <Form.Item name={['key', 'password']} label={t('PKCS#12 password')}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name={['key', 'keyAlias']} label={t('Key alias (required for multiple keys)')}>
            <Input />
          </Form.Item>
        </>
      )}
      {mode === 'pkcs11' && (
        <>
          <Alert
            type="info"
            message={t(
              'The module and key must already exist on the CA. Module setup and PIN management stay on the CA; this form does not manage HSM objects.',
            )}
          />
          <Form.Item
            name={['key', 'module']}
            label={t('CA module name')}
            rules={[{ required: true }, { pattern: /^[a-zA-Z0-9_.-]+$/ }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name={['key', 'slotIndex']}
            label={t('Slot index')}
            rules={[{ required: true }]}
          >
            <InputNumber min={0} />
          </Form.Item>
          <Form.Item name={['key', 'keyId']} label={t('Key ID (hex; choose ID or label)')}>
            <Input />
          </Form.Item>
          <Form.Item name={['key', 'keyLabel']} label={t('Key label')}>
            <Input />
          </Form.Item>
          <Form.Item
            name={['key', 'signatureAlgorithm']}
            label={t('Signature algorithm')}
            rules={[{ required: true }]}
          >
            <Select
              options={[
                'SHA256withRSA',
                'SHA384withRSA',
                'SHA512withRSA',
                'SHA256withECDSA',
                'SHA384withECDSA',
              ].map((value) => ({ value }))}
            />
          </Form.Item>
        </>
      )}
    </>
  )
}
