// License Apache License 2.0


import { useI18n } from '../i18n'
import React, { useState } from 'react'
import {
  ArrowRightOutlined,
  AuditOutlined,
  CheckCircleFilled,
  DownOutlined,
  FileProtectOutlined,
  LinkOutlined,
  PlusCircleOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import { Button, Card, Tag, Typography } from 'antd'
import { useCan } from '../auth'
import './GettingStartedGuide.css'
import type { DashboardData } from '../types/api'

type GuideStep = {
  title: string
  description: string
  action: string
  path: string
  icon: React.ReactNode
  color: string
  complete?: boolean
  permission: string
}

type Props = {
  data: DashboardData
  navigate: (path: string) => void
}

function FlowIllustration() {
  const { t } = useI18n()
  return (
    <div
      aria-label={t('CA management workflow diagram')}
      style={{ minWidth: 240, flex: '0 1 330px' }}
    >
      <svg
        viewBox="0 0 340 130"
        role="img"
        aria-labelledby="workflow-title workflow-description"
        style={{ width: '100%', height: 'auto' }}
      >
        <title id="workflow-title">{t('XiPKI management workflow')}</title>
        <desc id="workflow-description">
          {t(
            'Create a CA, connect policies and permissions, issue certificates, then publish and audit them.',
          )}
        </desc>
        <defs>
          <linearGradient id="guide-flow" x1="0" x2="1">
            <stop offset="0" stopColor="#e6f4ff" />
            <stop offset="1" stopColor="#f6ffed" />
          </linearGradient>
          <marker id="guide-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L7,3 z" fill="#8c8c8c" />
          </marker>
        </defs>
        <path
          d="M74 47 H126 M202 47 H254"
          stroke="#8c8c8c"
          strokeWidth="2"
          markerEnd="url(#guide-arrow)"
        />
        <path
          d="M164 72 V103 H285 V73"
          fill="none"
          stroke="#8c8c8c"
          strokeWidth="2"
          markerEnd="url(#guide-arrow)"
        />
        <g fontFamily="-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif" textAnchor="middle">
          <rect
            x="8"
            y="20"
            width="66"
            height="54"
            rx="12"
            fill="url(#guide-flow)"
            stroke="#91d5ff"
          />
          <text x="41" y="44" fontSize="12" fill="#0958d9">
            CA
          </text>
          <text x="41" y="61" fontSize="9" fill="#595959">
            {t('Root / Import')}
          </text>
          <rect x="126" y="20" width="76" height="54" rx="12" fill="#fff7e6" stroke="#ffd591" />
          <text x="164" y="44" fontSize="12" fill="#d46b08">
            {t('Policies')}
          </text>
          <text x="164" y="61" fontSize="9" fill="#595959">
            {t('Profiles · Access')}
          </text>
          <rect x="254" y="20" width="68" height="54" rx="12" fill="#f6ffed" stroke="#b7eb8f" />
          <text x="288" y="44" fontSize="12" fill="#389e0d">
            {t('Certs')}
          </text>
          <text x="288" y="61" fontSize="10" fill="#595959">
            {t('Issue')}
          </text>
          <rect x="238" y="93" width="94" height="27" rx="10" fill="#f9f0ff" stroke="#d3adf7" />
          <text x="285" y="111" fontSize="10" fill="#722ed1">
            {t('CRL · Audit')}
          </text>
        </g>
      </svg>
    </div>
  )
}

export default function GettingStartedGuide({ data, navigate }: Props) {
  const { t } = useI18n()
  const can = useCan()
  const [open, setOpen] = useState(true)
  const caCount = data.caNames?.length || 0
  const activeCaCount = data.successfulCaNames?.length || 0
  const policyCount =
    (data.certprofileCount || 0) + (data.requestorCount || 0) + (data.publisherCount || 0)

  const steps: GuideStep[] = [
    {
      title: t('Create or import a CA'),
      description: t(
        'Prepare a root CA, or import an existing CA certificate and signing key. New CAs start inactive.',
      ),
      action: t('Open CA management'),
      path: '/ca',
      icon: <PlusCircleOutlined />,
      color: '#1677ff',
      complete: caCount > 0,
      permission: 'CA_READ',
    },
    {
      title: t('Configure profiles and associations'),
      description: t(
        'Bind certificate profiles, requestors and publishers to control issuance permissions and status publication.',
      ),
      action: t('Configure profiles'),
      path: can('PROFILE_READ') ? '/profile' : '/ca',
      icon: <LinkOutlined />,
      color: '#d46b08',
      complete: policyCount > 0,
      permission: 'CA_READ',
    },
    {
      title: t('Activate and check status'),
      description: t(
        'Activate the CA and restart if needed. Confirm Active / Started status before issuing certificates.',
      ),
      action: t('Check CA status'),
      path: '/ca',
      icon: <SettingOutlined />,
      color: '#389e0d',
      complete: activeCaCount > 0,
      permission: 'CA_READ',
    },
    {
      title: t('Issue certificates'),
      description: t(
        'Upload a CSR, or generate a key and download a password-protected PKCS#12 certificate bundle.',
      ),
      action: t('Open certificate enrollment'),
      path: '/cert/enroll',
      icon: <FileProtectOutlined />,
      color: '#531dab',
      permission: 'CERT_ISSUE',
    },
    {
      title: t('CRL and audit'),
      description: t(
        'Generate CRLs, manage revocation and republication, and review operation records on the audit page.',
      ),
      action: t('Open system tools'),
      path: can('SYSTEM_READ')
        ? '/system'
        : can('AUDIT_READ')
          ? '/audit'
          : can('CRL_READ')
            ? '/crl'
            : '/ca',
      icon: <AuditOutlined />,
      color: '#c41d7f',
      permission: 'CA_READ',
    },
  ]

  return (
    <Card className="getting-started-guide" styles={{ body: { padding: 0 } }}>
      <div className="getting-started-heading">
        <Typography.Title level={5}>{t('Get started with XiPKI')}</Typography.Title>
        <Button
          type="text"
          onClick={() => setOpen((value) => !value)}
          icon={<DownOutlined rotate={open ? 180 : 0} />}
          aria-expanded={open}
        >
          {open ? t('Hide guide') : t('Show guide')}
        </Button>
      </div>
      {open && (
        <>
          <div className="getting-started-intro">
            <div>
              <Typography.Paragraph type="secondary">
                {t(
                  'Follow these steps for a complete CA management workflow. Open each page directly, then return here for the next step.',
                )}
              </Typography.Paragraph>
              <Tag color="blue">{t('Recommended workflow')}</Tag>
              {caCount > 0 && (
                <Tag color="green">{t('{count} CAs configured', { count: caCount })}</Tag>
              )}
            </div>
            <FlowIllustration />
          </div>
          <div className="getting-started-steps">
            {steps.map((step, index) => (
              <div
                className="getting-started-step"
                key={step.title}
                style={{ borderTopColor: step.color }}
              >
                <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                  <span style={{ color: step.color, fontSize: 22, lineHeight: 1 }}>
                    {step.icon}
                  </span>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <Typography.Text strong>
                      {index + 1}. {step.title}
                    </Typography.Text>
                    {step.complete && (
                      <CheckCircleFilled
                        aria-label={t('Configured')}
                        style={{ color: '#52c41a', marginLeft: 6 }}
                      />
                    )}
                    <Typography.Paragraph
                      type="secondary"
                      style={{ margin: '8px 0 4px', fontSize: 13 }}
                    >
                      {step.description}
                    </Typography.Paragraph>
                    <Button
                      type="link"
                      size="small"
                      disabled={!can(step.permission)}
                      onClick={() => navigate(step.path)}
                      style={{ padding: 0 }}
                    >
                      {step.action} <ArrowRightOutlined />
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </Card>
  )
}
