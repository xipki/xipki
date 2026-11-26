// License Apache License 2.0


import { useI18n } from '../../i18n'
import React, { useEffect, useState } from 'react'
import {
  Table,
  Button,
  Tag,
  Space,
  Modal,
  Input,
  Alert,
  message,
  Typography,
  Tabs,
  Tree,
  Spin,
  Empty,
} from 'antd'
import { caForest } from './ca-chain'
import {
  HistoryOutlined,
  PlusOutlined,
  ReloadOutlined,
  RightOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { caApi } from '../../api/ca'
import { useCan } from '../../auth'
import CaCreate from './CaCreate'
import { useReauthentication } from '../../components/Reauthentication'
import './CaList.css'
import type { CaSummary, DeleteImpact } from '../../types/api'

const CaList: React.FC = () => {
  const { t } = useI18n()
  const can = useCan()
  const [data, setData] = useState<CaSummary[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const view = searchParams.get('view') === 'hierarchy' ? 'hierarchy' : 'list'
  const [creating, setCreating] = useState(false)
  const [deleting, setDeleting] = useState<{ name: string; impact: DeleteImpact }>()
  const [confirmation, setConfirmation] = useState('')
  const { authorize, dialog } = useReauthentication()
  const caByName = new Map(data.map((ca) => [ca.name, ca]))

  const fetchData = () => {
    if (!can('CA_READ')) {
      setData([])
      setLoading(false)
      return
    }
    setLoading(true)
    caApi
      .list()
      .then((res) => setData(res.data.data || []))
      .catch(() => {
        /* API client reports failures and requests reauthentication. */
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleDelete = async (name: string) => {
    await caApi.remove(name, confirmation)
    setDeleting(undefined)
    setConfirmation('')
    message.success(t('CA {name} deleted', { name }))
    fetchData()
  }

  const columns = [
    {
      title: t('Name'),
      dataIndex: 'name',
      key: 'name',
      render: (name: string) => (
        <a onClick={() => navigate(`/ca/${encodeURIComponent(name)}`)}>{name}</a>
      ),
    },
    {
      title: t('Runtime'),
      dataIndex: 'runtimeState',
      render: (state: string) => (
        <Tag color={state === 'failed' ? 'red' : state === 'started' ? 'green' : 'default'}>
          {t(state)}
        </Tag>
      ),
    },
    {
      title: t('Status'),
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={status === 'active' ? 'green' : 'orange'}>{t(status)}</Tag>
      ),
    },
    { title: t('Subject'), dataIndex: 'subject', key: 'subject', ellipsis: true },
    { title: t('Signer Type'), dataIndex: 'signerType', key: 'signerType' },
    { title: t('Not After'), dataIndex: 'notAfter', key: 'notAfter' },
    {
      title: t('Actions'),
      key: 'actions',
      render: (_value: unknown, record: CaSummary) => (
        <Space>
          <Button size="small" onClick={() => navigate(`/ca/${encodeURIComponent(record.name)}`)}>
            {t('Detail / Configure')}
          </Button>
          {can('CA_RESTART', record) && (
            <Button
              size="small"
              onClick={() =>
                caApi
                  .restart(record.name)
                  .then(() => {
                    message.success(t('CA restarted'))
                    fetchData()
                  })
                  .catch(() => {})
              }
            >
              {t('Restart')}
            </Button>
          )}
          {can('CA_DELETE', record) && (
            <Button
              size="small"
              danger
              onClick={async () => {
                try {
                  const response = await caApi.deleteImpact(record.name)
                  setConfirmation('')
                  setDeleting({ name: record.name, impact: response.data.data })
                } catch {}
              }}
            >
              {t('Delete')}
            </Button>
          )}
        </Space>
      ),
    },
  ]

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
          {t('CA Management')}
        </Typography.Title>
        <Space wrap>
          {(can('CA_IMPORT') || can('CA_ISSUE_SUBCA')) && (
            <Button
              icon={<HistoryOutlined />}
              onClick={() => navigate('/ca/operations/enrollments')}
            >
              {t('CA enrollments')}
            </Button>
          )}
          {(can('CA_CREATE_ROOT') || can('CA_IMPORT') || can('CA_ISSUE_SUBCA')) && (
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreating(true)}>
              {t('Add CA')}
            </Button>
          )}
          {can('CA_READ') && (
            <Button icon={<ReloadOutlined />} onClick={fetchData}>
              {t('Refresh')}
            </Button>
          )}
        </Space>
      </div>
      {can('CA_READ') && (
        <Tabs
          activeKey={view}
          onChange={(key) => setSearchParams(key === 'hierarchy' ? { view: 'hierarchy' } : {})}
          items={[
            {
              key: 'list',
              label: t('CA list'),
              children: (
                <Table
                  columns={columns}
                  dataSource={data}
                  rowKey="name"
                  loading={loading}
                  scroll={{ x: 960 }}
                />
              ),
            },
            {
              key: 'hierarchy',
              label: t('CA hierarchy'),
              children: (
                <>
                  <Typography.Paragraph type="secondary">
                    {t(
                      'Only visible managed CAs and verified certificate relationships are shown. Permissions are not inherited from parent CAs.',
                    )}
                  </Typography.Paragraph>
                  {loading ? (
                    <Spin />
                  ) : data.length ? (
                    <div className="ca-hierarchy-viewport">
                      <Tree
                        className="ca-hierarchy-tree"
                        treeData={caForest(data)}
                        showLine={{ showLeafIcon: false }}
                        defaultExpandAll
                        titleRender={(node) => {
                          const ca = caByName.get(String(node.key))
                          return (
                            <div className="ca-hierarchy-node">
                              <SafetyCertificateOutlined className="ca-hierarchy-node-icon" />
                              <div className="ca-hierarchy-node-details">
                                <div className="ca-hierarchy-node-heading">
                                  <strong>{ca?.name || String(node.key)}</strong>
                                  {ca?.status && (
                                    <Tag color={ca.status === 'active' ? 'green' : 'orange'}>
                                      {t(ca.status)}
                                    </Tag>
                                  )}
                                  {ca?.runtimeState && (
                                    <Tag
                                      color={
                                        ca.runtimeState === 'started'
                                          ? 'green'
                                          : ca.runtimeState === 'failed'
                                            ? 'red'
                                            : 'default'
                                      }
                                    >
                                      {t(ca.runtimeState)}
                                    </Tag>
                                  )}
                                </div>
                                {ca?.subject && (
                                  <div className="ca-hierarchy-node-subject" title={ca.subject}>
                                    {ca.subject}
                                  </div>
                                )}
                              </div>
                              <RightOutlined className="ca-hierarchy-node-arrow" aria-hidden />
                            </div>
                          )
                        }}
                        onSelect={(keys) => {
                          if (keys[0]) navigate(`/ca/${encodeURIComponent(String(keys[0]))}`)
                        }}
                      />
                    </div>
                  ) : (
                    <Empty />
                  )}
                </>
              ),
            },
          ]}
        />
      )}
      {creating && (
        <CaCreate
          onClose={() => setCreating(false)}
          onCreated={(name) => {
            setCreating(false)
            if (can('CA_READ', name)) navigate(`/ca/${encodeURIComponent(name)}`)
            else fetchData()
          }}
        />
      )}
      <Modal
        title={t('Delete this CA configuration?')}
        open={!!deleting}
        onCancel={() => {
          setDeleting(undefined)
          setConfirmation('')
        }}
        okText={t('Delete')}
        okButtonProps={{ danger: true, disabled: confirmation !== deleting?.name }}
        onOk={() =>
          deleting &&
          authorize(t('Delete CA {name}', { name: deleting.name }), () =>
            handleDelete(deleting.name),
          )
        }
      >
        <Alert
          type="warning"
          showIcon
          message={t('This removes the CA and its associations. Export a controlled backup first.')}
        />
        <Typography.Paragraph style={{ marginTop: 16 }}>
          {t('Named role grants to revoke: {count}', {
            count: deleting?.impact.namedGrantCount || 0,
          })}
        </Typography.Paragraph>
        <Typography.Paragraph>
          {t('Profiles')}: {deleting?.impact.profiles?.join(', ') || t('None')}
        </Typography.Paragraph>
        <Typography.Paragraph>
          {t('Publishers')}: {deleting?.impact.publishers?.join(', ') || t('None')}
        </Typography.Paragraph>
        <Typography.Paragraph>
          {t('Aliases')}: {deleting?.impact.aliases?.join(', ') || t('None')}
        </Typography.Paragraph>
        <Typography.Paragraph>
          {t('Visible child CAs')}: {deleting?.impact.visibleChildCas?.join(', ') || t('None')}
        </Typography.Paragraph>
        <Typography.Paragraph>
          {t('Visible CA chain references')}:{' '}
          {deleting?.impact.visibleChainReferences?.join(', ') || t('None')}
        </Typography.Paragraph>
        <Typography.Paragraph>
          {t('Pending CA enrollments: {count}', {
            count: deleting?.impact.pendingEnrollmentCount || 0,
          })}
        </Typography.Paragraph>
        <Typography.Paragraph>
          {t(
            'Child CAs and issued certificates are not deleted or revoked automatically. Pending enrollments may require manual recovery.',
          )}
        </Typography.Paragraph>
        <Typography.Paragraph>
          {t('Enter the CA name to confirm deletion')}: {deleting?.name}
        </Typography.Paragraph>
        <Input
          aria-label={t('CA name confirmation')}
          value={confirmation}
          onChange={(event) => setConfirmation(event.target.value)}
        />
      </Modal>
      {dialog}
    </div>
  )
}

export default CaList
