// License Apache License 2.0


import { ArrowLeftOutlined } from '@ant-design/icons'
import { Button, Typography } from 'antd'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../../i18n'
import CaEnrollmentPage from './CaEnrollmentPage'

export default function CaEnrollmentRecords() {
  const { t } = useI18n()
  const navigate = useNavigate()

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
          marginBottom: 16,
        }}
      >
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t('CA enrollments')}
        </Typography.Title>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/ca')}>
          {t('CA Management')}
        </Button>
      </div>
      <CaEnrollmentPage />
    </div>
  )
}
