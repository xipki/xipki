// License Apache License 2.0


import React, { useEffect, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Collapse,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Spin,
  Tag,
  Typography,
  message,
} from 'antd'
import { DownloadOutlined, ReloadOutlined } from '@ant-design/icons'
import { useI18n } from '../../i18n'
import { certApi } from '../../api/cert'
import { useCan } from '../../auth'
import { useReauthentication } from '../../components/Reauthentication'
import { certificateValidity } from './certificate-validity'
import {
  revocationDisplay,
  withKnownRevocation,
  type CertificateRevocation,
} from './certificate-revocation'

type CertificateDetail = CertificateRevocation & {
  ca: string
  serialNumber: string
  subject: string
  issuer?: string
  notBefore: string
  notAfter: string
  profile?: string
  certPem?: string
}
export type CertificateTarget = CertificateRevocation & {
  ca: string
  serial: string
}
type Props = { target: CertificateTarget; onClose: () => void; onChanged: () => void }

const reasons = [
  'unspecified',
  'keyCompromise',
  'cACompromise',
  'affiliationChanged',
  'superseded',
  'cessationOfOperation',
  'certificateHold',
  'privilegeWithdrawn',
  'aACompromise',
]

const CertDetailDrawer: React.FC<Props> = ({ target, onClose, onChanged }) => {
  const { t } = useI18n()
  const can = useCan()
  const { authorize, dialog } = useReauthentication(`${target.ca}/${target.serial}`)
  const [detail, setDetail] = useState<CertificateDetail>()
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [revokeOpen, setRevokeOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [revokeForm] = Form.useForm<{ reason: string; invalidityTime?: string }>()
  const [deleteForm] = Form.useForm<{ serial: string }>()
  const alive = useRef(true)
  const generation = useRef(0)

  const load = () => {
    const request = ++generation.current
    setLoading(true)
    setDetail(undefined)
    void certApi
      .get(target.ca, target.serial)
      .then((res) => {
        if (alive.current && request === generation.current) {
          const remote = res.data.data as CertificateDetail
          setDetail({ ...withKnownRevocation(remote, target), ca: target.ca })
        }
      })
      .catch(() => {
        /* The common client reports the error. */
      })
      .finally(() => {
        if (alive.current && request === generation.current) setLoading(false)
      })
  }

  useEffect(() => {
    alive.current = true
    load()
    return () => {
      alive.current = false
      generation.current++
    }
  }, [target.ca, target.serial])

  const mutate = async (action: 'revoke' | 'unsuspend' | 'delete') => {
    if (!detail || working) return
    setWorking(true)
    try {
      if (action === 'revoke') {
        const values = await revokeForm.validateFields()
        await certApi.revoke(
          target.ca,
          target.serial,
          values.reason,
          values.invalidityTime || undefined,
        )
        if (alive.current) {
          setRevokeOpen(false)
          revokeForm.resetFields()
        }
      } else if (action === 'unsuspend') {
        await certApi.unsuspend(target.ca, target.serial)
      } else {
        await certApi.remove(target.ca, target.serial)
        if (alive.current) {
          setDeleteOpen(false)
          deleteForm.resetFields()
        }
      }
      if (!alive.current) return
      message.success(
        action === 'delete' ? t('Certificate deleted') : t('Certificate state refreshed'),
      )
      onChanged()
      onClose()
    } catch {
      /* Do not automatically retry certificate mutations. */
    } finally {
      if (alive.current) setWorking(false)
    }
  }

  const revocation = detail && revocationDisplay(detail)
  const held = revocation?.kind === 'hold'
  const validity = detail && certificateValidity(detail)
  const validityLabel =
    validity === 'expiring-soon'
      ? 'Expiring soon'
      : validity === 'not-yet-valid'
        ? 'Not yet valid'
        : validity === 'expired'
          ? 'Expired'
          : validity === 'valid'
            ? 'Within validity period'
            : 'Unknown validity'
  const validityColor =
    validity === 'valid'
      ? 'green'
      : validity === 'expired'
        ? 'red'
        : validity === 'expiring-soon'
          ? 'gold'
          : validity === 'not-yet-valid'
            ? 'blue'
            : 'default'

  return (
    <>
      <Drawer
        title={t('Certificate Detail')}
        open
        width="min(760px, 100vw)"
        onClose={() => {
          if (!working) onClose()
        }}
      >
        {loading ? (
          <Spin />
        ) : !detail ? (
          <Alert
            type="error"
            showIcon
            message={t('Certificate could not be loaded')}
            action={
              <Button icon={<ReloadOutlined />} onClick={load}>
                {t('Retry')}
              </Button>
            }
          />
        ) : (
          <>
            <Space wrap style={{ marginBottom: 18 }}>
              <Tag
                color={validityColor}
                title={validity === 'expiring-soon' ? t('Expires within 30 days') : undefined}
              >
                {t(validityLabel)}
              </Tag>
              <Tag color={revocation?.color}>{t(revocation?.label || '')}</Tag>
            </Space>
            <Descriptions className="cert-detail-descriptions" bordered size="small" column={1}>
              <Descriptions.Item label={t('Issuing CA')}>{detail.ca}</Descriptions.Item>
              <Descriptions.Item label={t('Profile:')}>{detail.profile || '—'}</Descriptions.Item>
              <Descriptions.Item label={t('Serial Number (hex)')}>
                <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>
                  {detail.serialNumber}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label={t('Subject:')}>
                <span style={{ overflowWrap: 'anywhere' }}>{detail.subject}</span>
              </Descriptions.Item>
              <Descriptions.Item label={t('Issuer:')}>
                <span style={{ overflowWrap: 'anywhere' }}>{detail.issuer || '—'}</span>
              </Descriptions.Item>
              <Descriptions.Item label={t('Not Before:')}>{detail.notBefore}</Descriptions.Item>
              <Descriptions.Item label={t('Not After:')}>{detail.notAfter}</Descriptions.Item>
              {detail.revoked && (
                <>
                  <Descriptions.Item label={t('Reason:')}>
                    {t(detail.revocationReason || '')}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('Revocation Time:')}>
                    {detail.revocationTime || '—'}
                  </Descriptions.Item>
                  {detail.invalidityTime && (
                    <Descriptions.Item label={t('Invalidity Time:')}>
                      {detail.invalidityTime}
                    </Descriptions.Item>
                  )}
                </>
              )}
            </Descriptions>
            <Space wrap style={{ marginTop: 20 }}>
              <Button
                icon={<DownloadOutlined />}
                href={certApi.downloadUrl(target.ca, target.serial, 'pem')}
                download
              >
                {t('Download PEM')}
              </Button>
              <Button
                icon={<DownloadOutlined />}
                href={certApi.downloadUrl(target.ca, target.serial, 'der')}
                download
              >
                {t('Download DER')}
              </Button>
              {(can('CERT_REVOKE', target.ca) || can('CERT_SUSPEND', target.ca)) &&
                (detail.revoked === false || held) && (
                  <Button
                    danger
                    disabled={working}
                    onClick={() => {
                      revokeForm.resetFields()
                      revokeForm.setFieldValue(
                        'reason',
                        can('CERT_REVOKE', target.ca) ? 'unspecified' : 'certificateHold',
                      )
                      setRevokeOpen(true)
                    }}
                  >
                    {t('Revoke / Hold')}
                  </Button>
                )}
              {held && can('CERT_UNSUSPEND', target.ca) && (
                <Popconfirm
                  title={t('Remove certificate hold?')}
                  onConfirm={() => void mutate('unsuspend')}
                >
                  <Button loading={working}>{t('Unsuspend')}</Button>
                </Popconfirm>
              )}
              {can('CERT_DELETE', target.ca) && (
                <Button
                  danger
                  disabled={working}
                  onClick={() => {
                    deleteForm.resetFields()
                    setDeleteOpen(true)
                  }}
                >
                  {t('Delete certificate')}
                </Button>
              )}
            </Space>
            {detail.certPem && (
              <Collapse
                style={{ marginTop: 20 }}
                items={[
                  {
                    key: 'pem',
                    label: t('Certificate PEM'),
                    children: (
                      <Input.TextArea
                        value={detail.certPem}
                        rows={12}
                        readOnly
                        style={{ fontFamily: 'monospace' }}
                      />
                    ),
                  },
                ]}
              />
            )}
          </>
        )}
      </Drawer>
      <Modal
        title={t('Revoke / Hold Certificate')}
        open={revokeOpen}
        onCancel={() => !working && setRevokeOpen(false)}
        onOk={() => void mutate('revoke')}
        confirmLoading={working}
      >
        <Form form={revokeForm} layout="vertical">
          <Form.Item name="reason" label={t('Reason')} rules={[{ required: true }]}>
            <Select
              options={reasons
                .filter((value) =>
                  can(value === 'certificateHold' ? 'CERT_SUSPEND' : 'CERT_REVOKE', target.ca),
                )
                .map((value) => ({ value, label: t(value) }))}
            />
          </Form.Item>
          <Form.Item
            name="invalidityTime"
            label={t('Invalidity Time (optional ISO-8601 UTC)')}
            rules={[
              {
                pattern: /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/,
                message: t('Use UTC ending in Z'),
              },
            ]}
          >
            <Input placeholder="2026-10-23T00:00:00Z" />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title={t('Delete Certificate')}
        open={deleteOpen}
        onCancel={() => !working && setDeleteOpen(false)}
        onOk={() => {
          void deleteForm
            .validateFields()
            .then(() => {
              setDeleteOpen(false)
              authorize(t('Delete Certificate'), () => mutate('delete'))
            })
            .catch(() => {})
        }}
        confirmLoading={working}
        okText={t('Delete')}
        okButtonProps={{ danger: true }}
      >
        <p>
          {t('Deletion removes the CA record. Enter the hexadecimal serial number to confirm:')}{' '}
          {target.serial}
        </p>
        <Form form={deleteForm}>
          <Form.Item
            name="serial"
            rules={[
              { required: true },
              {
                validator: (_, value) =>
                  value === target.serial
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('Serial number must match exactly'))),
              },
            ]}
          >
            <Input autoComplete="off" placeholder={t('Certificate serial number')} />
          </Form.Item>
        </Form>
      </Modal>
      {dialog}
    </>
  )
}

export default CertDetailDrawer
