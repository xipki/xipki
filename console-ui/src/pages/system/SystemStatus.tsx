// License Apache License 2.0


import { useI18n } from '../../i18n'
import React, { useEffect, useState } from 'react'
import {
  Alert,
  Card,
  Button,
  Space,
  message,
  Typography,
  Descriptions,
  Upload,
  Popconfirm,
  Input,
  Tabs,
  Form,
  Select,
  InputNumber,
  Modal,
} from 'antd'
import {
  ReloadOutlined,
  DownloadOutlined,
  UploadOutlined,
  PoweroffOutlined,
  UnlockOutlined,
} from '@ant-design/icons'
import { systemApi } from '../../api/system'
import { caApi } from '../../api/ca'
import { operationalCaNames } from '../../ca-availability'
import { saveDownload } from '../../api/cert'
import { useReauthentication } from '../../components/Reauthentication'
import { useCan } from '../../auth'
import { publisherApi } from '../../api/entities'
import { errorMessage } from '../../types/api'

const SystemStatus: React.FC = () => {
  const { t } = useI18n()
  const can = useCan()
  const { authorize, dialog } = useReauthentication()
  const [modal, modalContext] = Modal.useModal()
  const [status, setStatus] = useState<string>('')
  const [supportedTypes, setSupportedTypes] = useState<Record<string, string[]> | null>(null)
  const [tokenInfo, setTokenInfo] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [transferring, setTransferring] = useState(false)
  const [republishing, setRepublishing] = useState(false)
  const [caNames, setCaNames] = useState<string[]>([])
  const [casLoaded, setCasLoaded] = useState(false)
  const [publishers, setPublishers] = useState<string[]>([])
  const [republishForm] = Form.useForm<{
    caName: string
    publisherNames?: string[]
    numThreads: number
  }>()

  const fetchStatus = () => {
    if (can('SYSTEM_READ'))
      systemApi
        .status()
        .then((res) => setStatus(res.data.data || ''))
        .catch(() => {})
  }

  useEffect(() => {
    fetchStatus()
    if (['SIGNER_READ', 'PROFILE_READ', 'PUBLISHER_READ'].some((permission) => can(permission)))
      systemApi
        .supportedTypes()
        .then((res) => setSupportedTypes(res.data.data))
        .catch(() => {})
    if (can('CERT_REPUBLISH'))
      caApi
        .list()
        .then((res) => setCaNames(operationalCaNames(res.data.data || [], 'CERT_REPUBLISH', can)))
        .catch(() => {})
        .finally(() => setCasLoaded(true))
  }, [])

  const handleRestart = async () => {
    setLoading(true)
    try {
      await systemApi.restart()
      message.success(t('System restarted'))
      setTimeout(fetchStatus, 2000)
    } catch {
      /* Reported by common client. */
    } finally {
      setLoading(false)
    }
  }

  const handleUnlock = async () => {
    try {
      await systemApi.unlock()
      message.success(t('System unlocked'))
      fetchStatus()
    } catch {
      /* Reported by common client. */
    }
  }

  const handleNotify = async () => {
    try {
      await systemApi.notifyChange()
      message.success(t('Change notification sent'))
    } catch {
      /* Reported by common client. */
    }
  }

  const handleExport = async () => {
    if (transferring) return
    setTransferring(true)
    try {
      const res = await systemApi.exportConf()
      saveDownload(res.data, 'xipki-conf-export.zip')
    } catch {
      /* Reported by common client. */
    } finally {
      setTransferring(false)
    }
  }

  const handleImport = async (file: File) => {
    if (transferring) return false
    setTransferring(true)
    try {
      await systemApi.importConf(file)
      message.success(t('Configuration imported'))
      fetchStatus()
    } catch (e: unknown) {
      message.error(errorMessage(e, t('Import failed')))
    } finally {
      setTransferring(false)
    }
    return false
  }

  const handleTokenInfo = async () => {
    try {
      const res = await systemApi.tokenInfo(undefined, undefined, true)
      setTokenInfo(res.data.data || t('No token info available'))
    } catch {
      /* Reported by common client. */
    }
  }

  const confirmRepublish = (values: {
    caName: string
    publisherNames?: string[]
    numThreads: number
  }) => {
    if (republishing) return
    modal.confirm({
      title: t('Republish certificates for {name}?', { name: values.caName }),
      content: t(
        'This operation may take time. If it times out, verify the CA state before trying again.',
      ),
      onOk: async () => {
        setRepublishing(true)
        try {
          await systemApi.republish({
            ...values,
            publisherNames: values.publisherNames?.length ? values.publisherNames : undefined,
          })
          message.success(t('Certificate republishing completed'))
        } catch {
          /* Never automatically replay republish. */
        } finally {
          setRepublishing(false)
        }
      },
    })
  }

  return (
    <div>
      {modalContext}
      {dialog}
      <Typography.Title level={4}>{t('System Management')}</Typography.Title>

      <Tabs
        defaultActiveKey={
          can('SYSTEM_READ')
            ? 'status'
            : can('CONFIG_EXPORT') || can('CONFIG_IMPORT')
              ? 'config'
              : can('TOKEN_READ')
                ? 'token'
                : 'republish'
        }
        items={[
          {
            key: 'republish',
            label: t('Republish Certificates'),
            children: (
              <Card>
                {casLoaded && caNames.length === 0 && (
                  <Alert
                    type="info"
                    showIcon
                    message={t('No running CA is available for this operation.')}
                    style={{ marginBottom: 16 }}
                  />
                )}
                <Form
                  form={republishForm}
                  layout="vertical"
                  initialValues={{ numThreads: 5 }}
                  onFinish={confirmRepublish}
                >
                  <Form.Item name="caName" label="CA" rules={[{ required: true }]}>
                    <Select
                      options={caNames.map((value) => ({ value }))}
                      onChange={async (value) => {
                        setPublishers([])
                        republishForm.setFieldValue('publisherNames', [])
                        if (can('CA_PUBLISHER_READ', value))
                          try {
                            const res = await publisherApi.getForCa(value)
                            setPublishers(res.data.data || [])
                          } catch {
                            /* Reported by common client. */
                          }
                      }}
                    />
                  </Form.Item>
                  <Form.Item
                    name="publisherNames"
                    label={t('Publishers (leave empty for all bound publishers)')}
                  >
                    <Select mode="multiple" options={publishers.map((value) => ({ value }))} />
                  </Form.Item>
                  <Form.Item
                    name="numThreads"
                    label={t('Threads')}
                    rules={[{ required: true }, { type: 'integer', min: 1, max: 32 }]}
                  >
                    <InputNumber min={1} max={32} precision={0} />
                  </Form.Item>
                  <Button
                    type="primary"
                    htmlType="submit"
                    loading={republishing}
                    disabled={caNames.length === 0}
                  >
                    {t('Republish Certificates')}
                  </Button>
                </Form>
              </Card>
            ),
          },
          {
            key: 'status',
            label: t('Status & Control'),
            children: (
              <Space direction="vertical" size="large" style={{ width: '100%' }}>
                <Card title={t('System Status')}>
                  <Descriptions bordered size="small" column={1}>
                    <Descriptions.Item label={t('Status')}>
                      <Typography.Text
                        strong
                        style={{
                          color: status === 'STARTED_AS_MASTER' ? '#52c41a' : '#f5222d',
                        }}
                      >
                        {t(status)}
                      </Typography.Text>
                    </Descriptions.Item>
                  </Descriptions>
                  <Space style={{ marginTop: 16 }}>
                    <Button icon={<ReloadOutlined />} onClick={fetchStatus}>
                      {t('Refresh')}
                    </Button>
                    {can('SYSTEM_RESTART') && (
                      <Popconfirm
                        title={t('Restart the entire CA system?')}
                        onConfirm={() =>
                          authorize(t('Restart the entire CA system?'), handleRestart)
                        }
                      >
                        <Button icon={<PoweroffOutlined />} danger loading={loading}>
                          {t('Restart System')}
                        </Button>
                      </Popconfirm>
                    )}
                    {can('SYSTEM_UNLOCK') && (
                      <Button
                        icon={<UnlockOutlined />}
                        onClick={() => authorize(t('Unlock'), handleUnlock)}
                      >
                        {t('Unlock')}
                      </Button>
                    )}
                    {can('SYSTEM_NOTIFY_CHANGE') && (
                      <Button onClick={() => authorize(t('Notify Change'), handleNotify)}>
                        {t('Notify Change')}
                      </Button>
                    )}
                  </Space>
                </Card>

                {supportedTypes && (
                  <Card title={t('Supported Types')}>
                    <Descriptions bordered size="small" column={1}>
                      <Descriptions.Item label={t('Signer Types')}>
                        {(supportedTypes.signerTypes || []).join(', ')}
                      </Descriptions.Item>
                      <Descriptions.Item label={t('Certprofile Types')}>
                        {(supportedTypes.certprofileTypes || []).join(', ')}
                      </Descriptions.Item>
                      <Descriptions.Item label={t('Publisher Types')}>
                        {(supportedTypes.publisherTypes || []).join(', ')}
                      </Descriptions.Item>
                    </Descriptions>
                  </Card>
                )}
              </Space>
            ),
          },
          {
            key: 'config',
            label: t('Export / Import'),
            children: (
              <Card>
                <Space direction="vertical" size="large">
                  {can('CONFIG_EXPORT') && (
                    <div>
                      <Typography.Title level={5}>{t('Export Configuration')}</Typography.Title>
                      <Alert
                        type="warning"
                        showIcon
                        message={t(
                          'Native ZIP backups may contain CA private keys, passwords and other secrets. Store only in a controlled encrypted backup system.',
                        )}
                        style={{ marginBottom: 12 }}
                      />
                      <Popconfirm
                        title={t('Download sensitive CA backup?')}
                        description={t('The ZIP may contain CA private keys and passwords.')}
                        onConfirm={() =>
                          authorize(t('Download sensitive CA backup?'), handleExport)
                        }
                      >
                        <Button icon={<DownloadOutlined />} type="primary" loading={transferring}>
                          {t('Export as ZIP')}
                        </Button>
                      </Popconfirm>
                    </div>
                  )}
                  {can('CONFIG_IMPORT') && (
                    <div>
                      <Typography.Title level={5}>{t('Import Configuration')}</Typography.Title>
                      <Upload
                        beforeUpload={(file) => {
                          authorize(t('Import Configuration'), async () => {
                            await handleImport(file)
                          })
                          return false
                        }}
                        maxCount={1}
                        accept=".zip"
                      >
                        <Button icon={<UploadOutlined />} loading={transferring}>
                          {t('Select ZIP File to Import')}
                        </Button>
                      </Upload>
                    </div>
                  )}
                </Space>
              </Card>
            ),
          },
          {
            key: 'token',
            label: t('PKCS#11 Token Info'),
            children: (
              <Card>
                <Button onClick={handleTokenInfo} style={{ marginBottom: 16 }}>
                  {t('Load Token Info')}{' '}
                </Button>
                {tokenInfo && (
                  <Input.TextArea
                    value={tokenInfo}
                    rows={20}
                    readOnly
                    style={{ fontFamily: 'monospace', fontSize: 12 }}
                  />
                )}
              </Card>
            ),
          },
        ].filter((tab) =>
          tab.key === 'status'
            ? can('SYSTEM_READ')
            : tab.key === 'token'
              ? can('TOKEN_READ')
              : tab.key === 'config'
                ? can('CONFIG_EXPORT') || can('CONFIG_IMPORT')
                : can('CERT_REPUBLISH'),
        )}
      />
    </div>
  )
}

export default SystemStatus
