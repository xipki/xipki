// License Apache License 2.0


import { useI18n } from '../../i18n'
import React, { useEffect, useState } from 'react'
import {
  Button,
  DatePicker,
  Form,
  Input,
  Select,
  Space,
  Table,
  Typography,
  Tag,
  Modal,
  message,
} from 'antd'
import type { Dayjs } from 'dayjs'
import api from '../../api/client'
import { useCan } from '../../auth'
import { saveDownload } from '../../api/cert'

type AuditRow = {
  id: number
  event_time: string
  actor_username?: string
  action: string
  result: string
  request_path?: string
  failure_category?: string
  duration_ms?: number
  request_id?: string
  resource_type?: string
  resource_id?: string
  details_json?: string
  permission_codes?: string
}

type Filters = {
  actor?: string
  action?: string
  result?: string
  resourceType?: string
  resourceId?: string
  range?: [Dayjs, Dayjs]
}

const AuditList: React.FC = () => {
  const { t, locale } = useI18n()
  const can = useCan()
  const [exporting, setExporting] = useState(false)
  const [context, setContext] = useState<{
    items: Record<string, unknown>[]
    page: number
    hasMore: boolean
  }>()
  const [rows, setRows] = useState<AuditRow[]>([])
  const [loading, setLoading] = useState(false)
  const [page, setPage] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [filters, setFilters] = useState<Record<string, string | undefined>>({})

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    api
      .get('/api/audit', { params: { page, size: 50, ...filters }, signal: controller.signal })
      .then((response) => {
        setRows(response.data.data.items)
        setHasMore(response.data.data.hasMore)
      })
      .catch(() => {})
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [page, filters])

  const search = ({ range, ...values }: Filters) => {
    setPage(0)
    setFilters({ ...values, from: range?.[0]?.toISOString(), to: range?.[1]?.toISOString() })
  }
  const exportCsv = async () => {
    if (exporting) return
    setExporting(true)
    try {
      const response = await api.get('/api/audit/export', { params: filters, responseType: 'blob' })
      saveDownload(response.data, 'xipki-audit.csv')
      if (response.headers['x-export-truncated'] === 'true')
        message.warning(
          t('Export limited to 5000 events. Narrow the filters for remaining records.'),
        )
    } catch {
    } finally {
      setExporting(false)
    }
  }
  const loadContext = async (page = 0) => {
    try {
      const response = await api.get('/api/audit/context', { params: { page } })
      setContext(response.data.data)
    } catch {}
  }

  return (
    <>
      <Typography.Title level={3}>{t('Operation Audit')}</Typography.Title>
      <Space style={{ marginBottom: 16 }}>
        {can('AUDIT_EXPORT') && (
          <Button loading={exporting} onClick={() => void exportCsv()}>
            {t('Export audit CSV')}
          </Button>
        )}
        {can('AUDIT_CONTEXT_READ') && (
          <Button onClick={() => void loadContext()}>{t('Authorization context')}</Button>
        )}
      </Space>
      <Form layout="inline" onFinish={search} style={{ marginBottom: 16, rowGap: 8 }}>
        <Form.Item name="actor">
          <Input placeholder={t('Username')} allowClear />
        </Form.Item>
        <Form.Item name="action">
          <Input placeholder={t('Action (exact match)')} allowClear />
        </Form.Item>
        <Form.Item name="result">
          <Select
            placeholder={t('Result')}
            allowClear
            style={{ width: 140 }}
            options={['SUCCESS', 'FAILURE', 'ATTEMPT'].map((value) => ({ value, label: t(value) }))}
          />
        </Form.Item>
        <Form.Item name="resourceType">
          <Input placeholder={t('Resource type')} allowClear />
        </Form.Item>
        <Form.Item name="resourceId">
          <Input placeholder={t('Resource ID')} allowClear />
        </Form.Item>
        <Form.Item name="range">
          <DatePicker.RangePicker showTime />
        </Form.Item>
        <Form.Item>
          <Button htmlType="submit" type="primary">
            {t('Search')}
          </Button>
        </Form.Item>
      </Form>
      <Table<AuditRow>
        rowKey="id"
        loading={loading}
        dataSource={rows}
        pagination={false}
        expandable={{
          expandedRowRender: (row) => (
            <>
              <Typography.Text>
                {t('Request ID:')} {row.request_id} {t('· Resource:')} {row.resource_type}{' '}
                {row.resource_id}
              </Typography.Text>
              {row.details_json && (
                <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                  {row.details_json}
                </pre>
              )}
            </>
          ),
        }}
        columns={[
          {
            title: t('Time'),
            dataIndex: 'event_time',
            render: (value) => new Date(value).toLocaleString(locale),
          },
          {
            title: t('User'),
            dataIndex: 'actor_username',
            render: (value) => value || t('anonymous'),
          },
          { title: t('Action'), dataIndex: 'action' },
          {
            title: t('Permissions'),
            dataIndex: 'permission_codes',
            render: (value?: string) =>
              value
                ?.split(',')
                .filter(Boolean)
                .map((code) => (
                  <Tag key={code} title={code}>
                    {t(code)}
                  </Tag>
                )),
          },
          { title: t('Path'), dataIndex: 'request_path' },
          {
            title: t('Result'),
            dataIndex: 'result',
            render: (value) => (
              <Tag color={value === 'SUCCESS' ? 'green' : value === 'FAILURE' ? 'red' : 'blue'}>
                {t(value)}
              </Tag>
            ),
          },
          { title: t('Failure'), dataIndex: 'failure_category' },
          {
            title: t('Duration'),
            dataIndex: 'duration_ms',
            render: (value) => (value == null ? '' : `${value} ms`),
          },
        ]}
      />
      <Space style={{ marginTop: 16 }}>
        <Button disabled={page === 0 || loading} onClick={() => setPage(page - 1)}>
          {t('Previous')}
        </Button>
        <span>{t('Page {page}', { page: page + 1 })}</span>
        <Button disabled={!hasMore || loading} onClick={() => setPage(page + 1)}>
          {t('Next')}
        </Button>
      </Space>
      <Modal
        title={t('Authorization context')}
        open={!!context}
        onCancel={() => setContext(undefined)}
        footer={null}
        width={950}
      >
        <Typography.Paragraph>
          {t(
            'Read-only account and role scopes for audit verification. No passwords or private keys are included.',
          )}
        </Typography.Paragraph>
        <Table
          dataSource={context?.items}
          rowKey={(_, index) => String(index)}
          pagination={false}
          scroll={{ x: 1000 }}
          columns={[
            { title: t('Username'), dataIndex: 'username' },
            {
              title: t('Role'),
              dataIndex: 'role_name',
              render: (value) => (value ? t(value) : t('No grants')),
            },
            {
              title: t('Scope'),
              dataIndex: 'scope_type',
              render: (value) => (value ? t(value) : '—'),
            },
            { title: t('CA'), dataIndex: 'ca_name' },
            { title: t('CA certificate fingerprint'), dataIndex: 'ca_fingerprint', ellipsis: true },
            { title: t('Profile'), dataIndex: 'profile_name' },
          ]}
        />
        <Space style={{ marginTop: 16 }}>
          <Button
            disabled={!context || context.page === 0}
            onClick={() => void loadContext(context!.page - 1)}
          >
            {t('Previous')}
          </Button>
          <Button disabled={!context?.hasMore} onClick={() => void loadContext(context!.page + 1)}>
            {t('Next')}
          </Button>
        </Space>
      </Modal>
    </>
  )
}

export default AuditList
