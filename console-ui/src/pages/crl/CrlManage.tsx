// License Apache License 2.0


import { useI18n } from '../../i18n'
import React, { useEffect, useState } from 'react'
import { Alert, Card, Select, Button, Space, message, Typography, Input, Popconfirm } from 'antd'
import { DownloadOutlined, SyncOutlined } from '@ant-design/icons'
import { caApi } from '../../api/ca'
import { operationalCaNames } from '../../ca-availability'
import api from '../../api/client'
import { useCan } from '../../auth'
import { saveDownload } from '../../api/cert'
import { systemApi } from '../../api/system'
import { errorMessage } from '../../types/api'

const CrlManage: React.FC = () => {
  const { t } = useI18n()
  const can = useCan()
  const [caNames, setCaNames] = useState<string[]>([])
  const [casLoaded, setCasLoaded] = useState(false)
  const [selectedCa, setSelectedCa] = useState<string>('')
  const [generating, setGenerating] = useState(false)
  const [number, setNumber] = useState('')
  const [downloading, setDownloading] = useState(false)
  const [republishing, setRepublishing] = useState(false)

  useEffect(() => {
    caApi
      .list()
      .then((res) => {
        const names = operationalCaNames(res.data.data || [], 'CRL_READ', can)
        setCaNames(names)
        setSelectedCa(names[0] || '')
      })
      .catch(() => {})
      .finally(() => setCasLoaded(true))
  }, [])

  const generateCrl = async () => {
    if (!selectedCa) return
    setGenerating(true)
    try {
      const res = await api.post(`/api/crl/${encodeURIComponent(selectedCa)}/generate`, undefined, {
        timeout: 120000,
      })
      message.success(res.data.data || t('CRL generated'))
    } catch (e: unknown) {
      message.error(errorMessage(e, t('Failed to generate CRL')))
    } finally {
      setGenerating(false)
    }
  }

  const downloadCrl = async (historical = false) => {
    if (!selectedCa || downloading) return
    if (historical && (!/^[0-9]+$/.test(number) || BigInt(number) <= 0n)) {
      message.error(t('Enter a positive decimal CRL number'))
      return
    }
    setDownloading(true)
    try {
      const part = historical ? number : 'current'
      const response = await api.get(`/api/crl/${encodeURIComponent(selectedCa)}/${part}`, {
        responseType: 'blob',
      })
      saveDownload(response.data, `${selectedCa}-crl-${part}.crl`)
    } catch {
      /* Common client reports unavailable CRLs. */
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div>
      <Typography.Title level={4}>{t('CRL Management')}</Typography.Title>
      {casLoaded && caNames.length === 0 && (
        <Alert
          type="info"
          showIcon
          message={t('No running CA is available for this operation.')}
          style={{ marginBottom: 16 }}
        />
      )}

      <Card>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <div>
            <Typography.Text strong>{t('Select CA:')} </Typography.Text>
            <Select
              value={selectedCa}
              onChange={setSelectedCa}
              style={{ width: 300, marginLeft: 8 }}
              placeholder={t('Select CA')}
            >
              {caNames.map((n) => (
                <Select.Option key={n} value={n}>
                  {n}
                </Select.Option>
              ))}
            </Select>
          </div>

          <Space>
            {can('CRL_GENERATE', selectedCa) && (
              <Button
                type="primary"
                icon={<SyncOutlined />}
                onClick={generateCrl}
                loading={generating}
                disabled={!selectedCa}
              >
                {t('Generate CRL on Demand')}{' '}
              </Button>
            )}
            <Button
              icon={<DownloadOutlined />}
              onClick={() => void downloadCrl()}
              disabled={!selectedCa}
              loading={downloading}
            >
              {t('Download Current CRL')}{' '}
            </Button>
          </Space>

          <Space wrap>
            <Input
              aria-label={t('CRL number')}
              value={number}
              onChange={(event) => setNumber(event.target.value)}
              placeholder={t('Positive decimal CRL number')}
              style={{ width: 280 }}
            />
            <Button
              icon={<DownloadOutlined />}
              onClick={() => void downloadCrl(true)}
              disabled={!selectedCa || !number}
              loading={downloading}
            >
              {t('Download numbered CRL')}
            </Button>
          </Space>
          <Typography.Text type="secondary">
            {t(
              'Retrieve a known CRL number. The CA does not provide a list of all historical CRLs.',
            )}
          </Typography.Text>
          {can('CERT_REPUBLISH', selectedCa) && (
            <Popconfirm
              title={t('Republish certificates for {name}?', { name: selectedCa })}
              description={t(
                'This operation may take time. If it times out, verify the CA state before trying again.',
              )}
              onConfirm={async () => {
                if (republishing) return
                setRepublishing(true)
                try {
                  await systemApi.republish({ caName: selectedCa, numThreads: 5 })
                  message.success(t('Certificate republishing completed'))
                } catch {
                  /* Never automatically replay. */
                } finally {
                  setRepublishing(false)
                }
              }}
            >
              <Button loading={republishing} disabled={!selectedCa}>
                {t('Republish Certificates')}
              </Button>
            </Popconfirm>
          )}
        </Space>
      </Card>
    </div>
  )
}

export default CrlManage
