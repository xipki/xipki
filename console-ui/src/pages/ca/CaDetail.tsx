// License Apache License 2.0


import { useI18n } from '../../i18n'
import React, { useEffect, useRef, useState } from 'react'
import {
  Alert,
  Descriptions,
  Card,
  Tag,
  Button,
  Spin,
  Typography,
  Input,
  Tabs,
  Space,
  Popconfirm,
  message,
} from 'antd'
import { ArrowLeftOutlined } from '@ant-design/icons'
import { useParams, useNavigate } from 'react-router-dom'
import { caApi } from '../../api/ca'
import { useCan } from '../../auth'
import CaConfigEditor from './CaConfigEditor'
import CaAssociations from './CaAssociations'
import CaRevoke from './CaRevoke'
import { useReauthentication } from '../../components/Reauthentication'
import type { CaDetails } from '../../types/api'

const CaDetail: React.FC = () => {
  const { t } = useI18n()
  const { name: encodedName } = useParams<{ name: string }>()
  const name = encodedName || ''
  const [data, setData] = useState<CaDetails | null>(null)
  const [loading, setLoading] = useState(true)
  const [alias, setAlias] = useState('')
  const [busy, setBusy] = useState(false)
  const [revoking, setRevoking] = useState(false)
  const [loadedName, setLoadedName] = useState('')
  const identity = useRef({ name, revision: 0 })
  if (identity.current.name !== name)
    identity.current = { name, revision: identity.current.revision + 1 }
  const revision = identity.current.revision
  const alive = useRef(true)
  const currentRoute = () =>
    alive.current && identity.current.name === name && identity.current.revision === revision
  const generation = useRef(0)
  const can = useCan()
  const navigate = useNavigate()
  const { authorize, dialog } = useReauthentication(name)
  const refresh = () => {
    if (!currentRoute()) return
    const request = ++generation.current
    setLoadedName(name)
    setLoading(true)
    setData(null)
    if (!name) {
      setLoading(false)
      return
    }
    const current = () => generation.current === request && currentRoute()
    void caApi
      .get(name)
      .then((r) => {
        if (current()) setData(r.data.data)
      })
      .catch(() => {
        /* The API client reports failure; the empty state offers retry. */
      })
      .finally(() => {
        if (current()) setLoading(false)
      })
  }
  useEffect(() => {
    alive.current = true
    setAlias('')
    setRevoking(false)
    setBusy(false)
    refresh()
    return () => {
      alive.current = false
      generation.current++
    }
  }, [name])
  async function mutate(action: () => Promise<unknown>, ok: string) {
    if (!currentRoute() || loadedName !== name || loading || !data) return
    setBusy(true)
    try {
      await action()
      if (currentRoute()) {
        message.success(ok)
        refresh()
      }
    } catch {
      /* The API client reports failure. */
    } finally {
      if (currentRoute()) setBusy(false)
    }
  }
  async function download(format: string) {
    try {
      const r = await caApi.certificates(name, format)
      const url = URL.createObjectURL(r.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `${name}-certificates.${format}`
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch {
      /* client reports */
    }
  }
  if (loading || loadedName !== name) return <Spin size="large" />
  if (!data)
    return (
      <Alert
        type="error"
        message={t('CA could not be loaded')}
        action={<Button onClick={refresh}>{t('Retry')}</Button>}
      />
    )
  return (
    <div>
      <Button
        icon={<ArrowLeftOutlined />}
        onClick={() => navigate('/ca')}
        style={{ marginBottom: 16 }}
      >
        {t('Back')}
      </Button>
      <Typography.Title level={4}>CA: {data.name}</Typography.Title>
      {data.revocationCheck === 'known-revoked' && (
        <Alert type="error" showIcon message={t('known-revoked')} style={{ marginBottom: 16 }} />
      )}
      {data.runtimeState === 'failed' && (
        <Alert
          type="error"
          message={t('This CA failed to start and cannot issue certificates.')}
          style={{ marginBottom: 16 }}
        />
      )}
      {data.status === 'inactive' && (
        <Alert
          type="info"
          message={t(
            'This CA is inactive. Bind associations, activate it in Configuration and restart it if needed.',
          )}
          style={{ marginBottom: 16 }}
        />
      )}
      <Alert
        type="info"
        showIcon
        message={t(
          'A CA certificate uses its issuer AIA/CRL addresses. End-entity certificates use this CA publication settings. A Publisher alone does not provide an OCSP HTTP service.',
        )}
        style={{ marginBottom: 16 }}
      />
      <Tabs
        items={[
          {
            key: 'overview',
            label: t('Overview'),
            children: (
              <Card title={t('Basic Information')}>
                <Descriptions column={2} bordered size="small">
                  <Descriptions.Item label={t('Name')}>{data.name}</Descriptions.Item>
                  <Descriptions.Item label={t('Status')}>
                    <Tag>{t(data.status || 'unknown')}</Tag> {t('Runtime')}:{' '}
                    {t(data.runtimeState || 'unknown')}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Subject')} span={2}>
                    {data.subject}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Serial')}>{data.serialNumber}</Descriptions.Item>
                  <Descriptions.Item label={t('Signer')}>{data.signerType}</Descriptions.Item>
                  <Descriptions.Item label={t('Issuer')} span={2}>
                    {data.issuer || '—'}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Chain validation')} span={2}>
                    {t(data.chainStatus || 'unverified')}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Revocation check')} span={2}>
                    {t(data.revocationCheck || 'unknown')}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Certificate fingerprint')} span={2}>
                    <Typography.Text copyable style={{ wordBreak: 'break-all' }}>
                      {data.certificateFingerprint}
                    </Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Parent certificate fingerprint')} span={2}>
                    <Typography.Text style={{ wordBreak: 'break-all' }}>
                      {data.parentCertificateFingerprint || '—'}
                    </Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item label={t('CA path length')}>
                    {data.pathLength === 2147483647 ? '∞' : data.pathLength}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Certificate chain')} span={2}>
                    <Space direction="vertical">
                      {(data.chainCertificateFingerprints || []).map((fingerprint: string) => (
                        <Typography.Text
                          key={fingerprint}
                          style={{ wordBreak: 'break-all', fontFamily: 'monospace' }}
                        >
                          {fingerprint}
                        </Typography.Text>
                      ))}
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Not Before')}>{data.notBefore}</Descriptions.Item>
                  <Descriptions.Item label={t('Not After')}>{data.notAfter}</Descriptions.Item>
                  <Descriptions.Item label={t('Max Validity')}>
                    {data.maxValidity}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Serial bytes')}>
                    {data.serialNoLen}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Revocation')} span={2}>
                    {data.revocationInfo
                      ? JSON.stringify(data.revocationInfo)
                      : t(data.revocationCheck || 'unknown')}
                  </Descriptions.Item>
                </Descriptions>
                <Space style={{ marginTop: 16 }}>
                  {(data.permissions || []).map((p: string) => (
                    <Tag key={p}>{p}</Tag>
                  ))}
                </Space>
                <Space style={{ display: 'flex', marginTop: 16 }}>
                  {can('CA_RESTART', data) && (
                    <Button
                      loading={busy}
                      onClick={() => void mutate(() => caApi.restart(name), t('CA restarted'))}
                    >
                      {t('Restart CA')}
                    </Button>
                  )}
                  {data.revocationInfo
                    ? can('CA_UNREVOKE', data) && (
                        <Popconfirm
                          title={t('Unrevoke this CA?')}
                          onConfirm={() =>
                            authorize(t('Unrevoke CA'), () =>
                              mutate(() => caApi.unrevoke(name), t('CA unrevoked')),
                            )
                          }
                        >
                          <Button>{t('Unrevoke CA')}</Button>
                        </Popconfirm>
                      )
                    : can('CA_REVOKE', data) && (
                        <Button danger disabled={busy} onClick={() => setRevoking(true)}>
                          {t('Revoke CA')}
                        </Button>
                      )}
                </Space>
              </Card>
            ),
          },
          ...(can('CA_CONFIG_READ', data)
            ? [
                {
                  key: 'config',
                  label: t('Configuration'),
                  children: <CaConfigEditor name={name} resource={data} onSaved={refresh} />,
                },
              ]
            : []),
          {
            key: 'cert',
            label: t('Certificate chain'),
            children: (
              <Card>
                <Space>
                  <Button onClick={() => void download('pem')}>{t('Download PEM chain')}</Button>
                  <Button onClick={() => void download('der')}>{t('Download DER')}</Button>
                </Space>
                <Input.TextArea
                  value={data.certPem}
                  rows={15}
                  readOnly
                  style={{ fontFamily: 'monospace', marginTop: 16 }}
                />
              </Card>
            ),
          },
          {
            key: 'aliases',
            label: t('Aliases'),
            children: (
              <Card>
                {(data.aliases || []).map((a: string) => (
                  <Space key={a} style={{ marginRight: 12 }}>
                    <Tag>{a}</Tag>
                    {can('CA_ALIAS_DELETE', data) && (
                      <Popconfirm
                        title={t('Remove alias?')}
                        onConfirm={() => mutate(() => caApi.removeAlias(a), t('Alias removed'))}
                      >
                        <Button size="small">{t('Remove')}</Button>
                      </Popconfirm>
                    )}
                  </Space>
                ))}
                {can('CA_ALIAS_CREATE', data) && (
                  <Space style={{ display: 'flex', marginTop: 16 }}>
                    <Input
                      value={alias}
                      onChange={(e) => setAlias(e.target.value)}
                      placeholder={t('New alias')}
                    />
                    <Button
                      disabled={!alias.trim()}
                      onClick={() =>
                        void mutate(() => caApi.addAlias(alias, name), t('Alias added')).then(() =>
                          setAlias(''),
                        )
                      }
                    >
                      {t('Add alias')}
                    </Button>
                  </Space>
                )}
              </Card>
            ),
          },
          ...(['CA_PROFILE_READ', 'CA_PUBLISHER_READ', 'CA_REQUESTOR_READ'].some((permission) =>
            can(permission, data),
          )
            ? [
                {
                  key: 'associations',
                  label: t('Associations'),
                  children: <CaAssociations caName={name} resource={data} />,
                },
              ]
            : []),
        ]}
      />
      {revoking && <CaRevoke name={name} onClose={() => setRevoking(false)} onSaved={refresh} />}
      {dialog}
    </div>
  )
}
export default CaDetail
