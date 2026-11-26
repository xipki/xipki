// License Apache License 2.0


import { useI18n } from '../i18n'
import React, { useEffect, useState } from 'react'
import { Card, Statistic, Tag, Typography, Spin, List } from 'antd'
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  PauseCircleOutlined,
  SafetyCertificateOutlined,
  KeyOutlined,
  UserOutlined,
  CloudUploadOutlined,
} from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { systemApi } from '../api/system'
import GettingStartedGuide from '../components/GettingStartedGuide'
import QuickStartWizard from '../components/QuickStartWizard'
import { useCan } from '../auth'
import './Dashboard.css'
import type { DashboardData } from '../types/api'

const Dashboard: React.FC = () => {
  const { t } = useI18n()
  const can = useCan()
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    systemApi
      .dashboard()
      .then((res) => setData(res.data.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <Spin size="large" />
  if (!data) return <div>{t('Failed to load dashboard')}</div>

  const statusColor: Record<string, string> = {
    STARTED_AS_MASTER: 'green',
    STARTED_AS_SLAVE: 'blue',
    ERROR: 'red',
    LOCK_FAILED: 'red',
    NOT_INITED: 'orange',
    INITIALIZING: 'orange',
  }

  return (
    <div>
      <Typography.Title level={4}>{t('System Dashboard')}</Typography.Title>

      <QuickStartWizard />

      <div className="dashboard-stat-grid">
        <Card className="dashboard-stat-card dashboard-system-status">
          <Statistic
            title={t('System Status')}
            value={t(data.systemStatus)}
            valueStyle={{ color: statusColor[data.systemStatus] || '#999' }}
          />
        </Card>
        <Card className="dashboard-stat-card" hoverable onClick={() => navigate('/ca')}>
          <Statistic
            title={t('Active CAs')}
            value={data.successfulCaNames?.length || 0}
            prefix={<CheckCircleOutlined style={{ color: '#52c41a' }} />}
            suffix={`/ ${data.caNames?.length || 0}`}
          />
        </Card>
        <Card className="dashboard-stat-card">
          <Statistic
            title={t('Failed CAs')}
            value={data.failedCaNames?.length || 0}
            prefix={<CloseCircleOutlined style={{ color: '#f5222d' }} />}
          />
        </Card>
        <Card className="dashboard-stat-card">
          <Statistic
            title={t('Inactive CAs')}
            value={data.inactiveCaNames?.length || 0}
            prefix={<PauseCircleOutlined style={{ color: '#faad14' }} />}
          />
        </Card>
      </div>

      <div className="dashboard-stat-grid dashboard-resource-grid">
        {can('PROFILE_READ') && (
          <Card className="dashboard-stat-card" hoverable onClick={() => navigate('/profile')}>
            <Statistic
              title={t('Cert Profiles')}
              value={data.certprofileCount || 0}
              prefix={<SafetyCertificateOutlined />}
            />
          </Card>
        )}
        {can('SIGNER_READ') && (
          <Card className="dashboard-stat-card" hoverable onClick={() => navigate('/signer')}>
            <Statistic
              title={t('Signers')}
              value={data.signerCount || 0}
              prefix={<KeyOutlined />}
            />
          </Card>
        )}
        {can('REQUESTOR_READ') && (
          <Card className="dashboard-stat-card" hoverable onClick={() => navigate('/requestor')}>
            <Statistic
              title={t('Requestors')}
              value={data.requestorCount || 0}
              prefix={<UserOutlined />}
            />
          </Card>
        )}
        {can('PUBLISHER_READ') && (
          <Card className="dashboard-stat-card" hoverable onClick={() => navigate('/publisher')}>
            <Statistic
              title={t('Publishers')}
              value={data.publisherCount || 0}
              prefix={<CloudUploadOutlined />}
            />
          </Card>
        )}
      </div>

      <GettingStartedGuide data={data} navigate={navigate} />

      {data.failedCaNames?.length > 0 && (
        <Card title={t('Failed CAs')} style={{ marginTop: 24 }}>
          <List
            dataSource={data.failedCaNames}
            renderItem={(name: string) => (
              <List.Item>
                <Tag color="red">{name}</Tag>
              </List.Item>
            )}
          />
        </Card>
      )}
    </div>
  )
}

export default Dashboard
