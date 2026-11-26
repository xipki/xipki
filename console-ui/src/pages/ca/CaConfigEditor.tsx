// License Apache License 2.0


import { useI18n } from '../../i18n'
import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Card, Checkbox, Collapse, Form, Input, message } from 'antd'
import { caApi } from '../../api/ca'
import CaConfigFields, { configuration, configValues } from './CaConfigFields'
import CaKeyFields from './CaKeyFields'
import { useCan } from '../../auth'
import { useReauthentication } from '../../components/Reauthentication'
import { configurationChanges } from './ca-config-policy'
import type { CaResource } from '../../access-policy'
import type { EntityPayload, FormValues } from '../../types/api'

export default function CaConfigEditor({
  name,
  resource = name,
  onSaved,
}: {
  name: string
  resource?: CaResource
  onSaved: () => void
}) {
  const { t } = useI18n()
  const [form] = Form.useForm()
  const initial = useRef<Record<string, unknown>>({})
  const can = useCan()
  const canChange = (permission: string) => can(permission, resource)
  const writable = [
    'CA_CONFIG_UPDATE',
    'CA_STATUS_UPDATE',
    'CA_KEY_REPLACE',
    'CA_CERT_REPLACE',
    'CA_CRYPTO_CONFIG_UPDATE',
    'CA_ENGINE_PERMISSIONS_UPDATE',
  ].some(canChange)
  const { authorize, dialog } = useReauthentication()
  const [loadState, setLoadState] = useState<{
    name: string
    status: 'loading' | 'ready' | 'error'
  }>({ name, status: 'loading' })
  const [revision, setRevision] = useState(0)
  const [busy, setBusy] = useState(false)
  const generation = useRef(0)
  const activeName = useRef(name)
  activeName.current = name
  const replacingSigner = Form.useWatch('replaceSigner', form)
  const replacingCert = Form.useWatch('replaceCertificates', form)
  useEffect(() => {
    const current = ++generation.current
    form.resetFields()
    setBusy(false)
    setLoadState({ name, status: 'loading' })
    void caApi
      .config(name)
      .then((r) => {
        if (generation.current !== current) return
        const values = configValues(r.data.data as FormValues)
        initial.current = configuration(values)
        form.setFieldsValue(values)
        setLoadState({ name, status: 'ready' })
      })
      .catch(() => {
        if (generation.current === current) setLoadState({ name, status: 'error' })
      })
    return () => {
      generation.current++
    }
  }, [name, revision, form])
  const ready = loadState.name === name && loadState.status === 'ready'
  async function save() {
    if (!ready || busy) return
    const current = generation.current
    const stillCurrent = () => generation.current === current && activeName.current === name
    setBusy(true)
    try {
      const values: FormValues = await form.validateFields()
      if (!stillCurrent()) return
      const next = configuration(values)
      if (values.replaceSigner === true)
        Object.assign(next, { replaceSigner: true, key: values.key })
      if (values.replaceCertificates === true)
        Object.assign(next, {
          replaceCertificates: true,
          encodedCert: values.encodedCert,
          encodedCertchain:
            typeof values.encodedCertchain === 'string' && values.encodedCertchain
              ? JSON.parse(values.encodedCertchain)
              : [],
        })
      const result = configurationChanges(initial.current, next, canChange)
      if (
        values.acceptUnknownRevocation === true &&
        (result.status === 'active' || result.replaceCertificates)
      )
        result.acceptUnknownRevocation = true
      const update = async () => {
        if (!stillCurrent()) return
        setBusy(true)
        try {
          await caApi.update(name, result as EntityPayload)
          if (!stillCurrent()) return
          form.resetFields()
          setLoadState({ name, status: 'loading' })
          setRevision((value) => value + 1)
          message.success(t('CA configuration saved'))
          onSaved()
        } finally {
          if (stillCurrent()) setBusy(false)
        }
      }
      if (
        [
          'key',
          'replaceSigner',
          'encodedCert',
          'encodedCertchain',
          'replaceCertificates',
          'permissions',
          'acceptUnknownRevocation',
        ].some((field) => field in result)
      )
        authorize(t('Save configuration'), update)
      else await update()
    } catch (e: unknown) {
      if (
        stillCurrent() &&
        !(e && typeof e === 'object' && 'errorFields' in e) &&
        !(e && typeof e === 'object' && 'isAxiosError' in e)
      ) {
        const detail =
          e && typeof e === 'object' && 'message' in e && typeof e.message === 'string'
            ? e.message
            : t('Operation failed')
        message.error(t(detail))
      }
    } finally {
      if (stillCurrent()) setBusy(false)
    }
  }
  if (loadState.name === name && loadState.status === 'error')
    return (
      <Card title={t('CA configuration')}>
        <Alert
          type="error"
          showIcon
          message={t('Unable to load CA configuration. Retry before making changes.')}
        />
        <Button onClick={() => setRevision((value) => value + 1)} style={{ marginTop: 16 }}>
          {t('Retry loading configuration')}
        </Button>
      </Card>
    )
  if (!ready)
    return (
      <Card>
        <span>{t('Loading configuration…')}</span>
      </Card>
    )
  return (
    <Card title={t('CA configuration')}>
      {!writable && <Alert type="info" showIcon message={t('Read-only configuration')} />}
      <Form form={form} layout="vertical" disabled={busy} preserve={false}>
        <CaConfigFields
          canChange={canChange}
          activationAllowed={
            typeof resource === 'object' &&
            'chainStatus' in resource &&
            resource.chainStatus === 'verified' &&
            !('revocationInfo' in resource && resource.revocationInfo) &&
            !('revocationCheck' in resource && resource.revocationCheck === 'known-revoked')
          }
        />
        {canChange('CA_STATUS_UPDATE') && (
          <Form.Item name="acceptUnknownRevocation" valuePropName="checked">
            <Checkbox>
              {t(
                'I accept that external revocation status cannot be verified. Known local revocations are still rejected.',
              )}
            </Checkbox>
          </Form.Item>
        )}
        {(canChange('CA_KEY_REPLACE') || canChange('CA_CERT_REPLACE')) && (
          <Collapse
            items={[
              {
                key: 'secret',
                label: t('Explicitly replace signer or certificates'),
                children: (
                  <>
                    <Alert
                      type="warning"
                      message={t(
                        'Existing signer secrets are never shown. Leave replacement unchecked to preserve them.',
                      )}
                    />
                    {canChange('CA_KEY_REPLACE') && (
                      <Form.Item name="replaceSigner" valuePropName="checked">
                        <Checkbox>{t('Replace signing material')}</Checkbox>
                      </Form.Item>
                    )}
                    {replacingSigner && <CaKeyFields />}
                    {canChange('CA_CERT_REPLACE') && (
                      <Form.Item name="replaceCertificates" valuePropName="checked">
                        <Checkbox>{t('Replace CA certificate chain')}</Checkbox>
                      </Form.Item>
                    )}
                    {replacingCert && (
                      <>
                        <Form.Item name="encodedCert" label={t('CA certificate')}>
                          <Input.TextArea rows={4} />
                        </Form.Item>
                        <Form.Item name="encodedCertchain" label={t('Issuer chain JSON array')}>
                          <Input.TextArea rows={4} />
                        </Form.Item>
                      </>
                    )}
                  </>
                ),
              },
            ]}
          />
        )}
        {writable && (
          <Button
            type="primary"
            loading={busy}
            onClick={() => void save()}
            style={{ marginTop: 16 }}
          >
            {t('Save configuration')}
          </Button>
        )}
      </Form>
      {dialog}
    </Card>
  )
}
