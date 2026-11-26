// License Apache License 2.0


import { useI18n } from '../../i18n'
import { Alert, Collapse, Form, Input, InputNumber, Select, Switch } from 'antd'
import type { FormValues } from '../../types/api'

export const permissions = [
  'all',
  'enroll_cert',
  'revoke_cert',
  'unsuspend_cert',
  'remove_cert',
  'reenroll_cert',
  'gen_crl',
  'get_crl',
  'enroll_cross',
  'gen_keypair',
  'get_cert',
]
export function configValues(config: FormValues = {}) {
  const status = typeof config.status === 'string' ? config.status : 'inactive'
  const maxValidity = typeof config.maxValidity === 'string' ? config.maxValidity : '365d'
  const perms = Array.isArray(config.permissions)
    ? config.permissions.filter((value): value is string => typeof value === 'string')
    : ['all']
  const saveCert = typeof config.saveCert === 'boolean' ? config.saveCert : true
  const saveKeypair = typeof config.saveKeypair === 'boolean' ? config.saveKeypair : false
  const serialNoLen = typeof config.serialNoLen === 'number' ? config.serialNoLen : 20
  const advanced: FormValues = { ...config }
  for (const key of [
    'status',
    'maxValidity',
    'permissions',
    'saveCert',
    'saveKeypair',
    'serialNoLen',
  ])
    delete advanced[key]
  for (const key of [
    'signerType',
    'signerConf',
    'key',
    'replaceSigner',
    'replaceCertificates',
    'encodedCert',
    'encodedCertchain',
  ])
    delete advanced[key]
  return {
    status,
    maxValidity,
    permissions: perms,
    saveCert,
    saveKeypair,
    serialNoLen,
    advanced: JSON.stringify(advanced, null, 2),
  }
}
export function configuration(values: FormValues) {
  const advancedText = typeof values.advanced === 'string' ? values.advanced : ''
  const advanced = advancedText.trim() ? JSON.parse(advancedText) : {}
  if (!advanced || Array.isArray(advanced) || typeof advanced !== 'object')
    throw new Error('Advanced configuration must be a JSON object')
  return {
    ...advanced,
    status: values.status,
    maxValidity: values.maxValidity,
    permissions: values.permissions,
    saveCert: values.saveCert,
    saveKeypair: values.saveKeypair,
    serialNoLen: values.serialNoLen,
  }
}
export default function CaConfigFields({
  canChange = () => true,
  activationAllowed = false,
}: {
  canChange?: (permission: string) => boolean
  activationAllowed?: boolean
}) {
  const { t } = useI18n()
  return (
    <>
      <Form.Item name="status" label={t('Status')}>
        <Select
          disabled={!canChange('CA_STATUS_UPDATE')}
          options={['inactive', 'active'].map((value) => ({
            value,
            label: t(value),
            disabled: value === 'active' && !activationAllowed,
          }))}
        />
      </Form.Item>
      <Form.Item
        name="maxValidity"
        label={t('Maximum issued certificate validity')}
        rules={[
          { required: true },
          { pattern: /^[1-9][0-9]*[ymdh]$/, message: t('Example: 365d or 2y') },
        ]}
      >
        <Input disabled={!canChange('CA_CONFIG_UPDATE')} placeholder="365d" />
      </Form.Item>
      <Form.Item name="permissions" label={t('CA permissions')} rules={[{ required: true }]}>
        <Select
          disabled={!canChange('CA_ENGINE_PERMISSIONS_UPDATE')}
          mode="multiple"
          options={permissions.map((value) => ({ value }))}
        />
      </Form.Item>
      <Form.Item name="serialNoLen" label={t('Serial number bytes')} rules={[{ required: true }]}>
        <InputNumber disabled={!canChange('CA_CONFIG_UPDATE')} min={1} max={20} />
      </Form.Item>
      <Form.Item name="saveCert" label={t('Save certificates')} valuePropName="checked">
        <Switch disabled={!canChange('CA_CONFIG_UPDATE')} />
      </Form.Item>
      <Form.Item
        name="saveKeypair"
        label={t('Save issued private keys in CA')}
        valuePropName="checked"
      >
        <Switch disabled={!canChange('CA_CRYPTO_CONFIG_UPDATE')} />
      </Form.Item>
      <Collapse
        items={[
          {
            key: 'advanced',
            label: t('Advanced CA configuration'),
            children: (
              <>
                <Alert
                  type="info"
                  showIcon
                  message={t(
                    'Supported: crlControl, ctlogControl, revokeSuspendedControl, crlSignerName, keypairGenNames, validityMode, keepExpiredCertDays, expirationPeriod, extraControl, caUris, numCrls. Omitted fields are preserved. Use XiPKI NULL where a control supports clearing. Signer and certificate changes use explicit replacement below.',
                  )}
                />
                <Form.Item name="advanced" label={t('Configuration JSON')}>
                  <Input.TextArea
                    disabled={
                      !canChange('CA_CONFIG_UPDATE') && !canChange('CA_CRYPTO_CONFIG_UPDATE')
                    }
                    rows={10}
                    style={{ fontFamily: 'monospace' }}
                  />
                </Form.Item>
              </>
            ),
          },
        ]}
      />
    </>
  )
}
