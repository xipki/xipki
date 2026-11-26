// License Apache License 2.0


import { useI18n } from '../../i18n'
import React, { useState } from 'react'
import { Button, Modal, Form, Input, Select, message } from 'antd'
import EntityCrudPage from '../../components/EntityCrudPage'
import { requestorApi } from '../../api/entities'
import { caApi } from '../../api/ca'
import { useCan } from '../../auth'
import { useReauthentication } from '../../components/Reauthentication'
import { errorMessage, type CaSummary, type FormValues } from '../../types/api'

const RequestorList: React.FC = () => {
  const { t } = useI18n()
  const can = useCan()
  const { authorize, dialog } = useReauthentication()
  const [name, setName] = useState<string | null>(null)
  const [caNames, setCaNames] = useState<string[]>([])
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm()
  const open = async (requestor: string) => {
    try {
      const res = await caApi.list()
      setCaNames(
        (res.data.data || [])
          .filter(
            (ca: CaSummary) =>
              can('CA_REQUESTOR_BIND', ca) && can('CA_REQUESTOR_ACCESS_UPDATE', ca),
          )
          .map((ca: CaSummary) => ca.name),
      )
      form.resetFields()
      setName(requestor)
    } catch (e: unknown) {
      message.error(errorMessage(e, t('Could not load CAs')))
    }
  }
  const bind = async (values: FormValues) => {
    if (!name || saving) return
    if (typeof values.ca !== 'string' || typeof values.profiles !== 'string') return
    setSaving(true)
    try {
      await requestorApi.addToCa(name, values.ca, {
        permissions: values.permissions,
        profiles: values.profiles
          .split(',')
          .map((s: string) => s.trim())
          .filter(Boolean),
      })
      message.success(t('Requestor bound to CA'))
      setName(null)
      form.resetFields()
    } catch (e: unknown) {
      message.error(errorMessage(e, t('Binding failed')))
    } finally {
      setSaving(false)
    }
  }
  return (
    <>
      <EntityCrudPage
        resource="REQUESTOR"
        title={t('Requestors')}
        api={requestorApi}
        extraActions={(record) =>
          can('CA_REQUESTOR_BIND') &&
          can('CA_REQUESTOR_ACCESS_UPDATE') && (
            <Button size="small" onClick={() => open(record.name)}>
              {t('Add to CA')}
            </Button>
          )
        }
      />
      <Modal
        title={t('Bind {name} to CA', { name: name || '' })}
        open={!!name}
        confirmLoading={saving}
        onCancel={() => {
          if (!saving) {
            setName(null)
            form.resetFields()
          }
        }}
        onOk={() => form.submit()}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={(values) =>
            authorize(t('Confirm external client access change'), () => bind(values))
          }
          initialValues={{ profiles: 'all' }}
        >
          <Form.Item name="ca" label="CA" rules={[{ required: true }]}>
            <Select options={caNames.map((value) => ({ value }))} />
          </Form.Item>
          <Form.Item name="permissions" label={t('Permissions')} rules={[{ required: true }]}>
            <Select
              mode="multiple"
              options={[
                'enroll_cert',
                'revoke_cert',
                'unsuspend_cert',
                'remove_cert',
                'reenroll_cert',
                'get_crl',
                'enroll_cross',
                'gen_keypair',
                'get_cert',
                'all',
              ].map((value) => ({ value }))}
            />
          </Form.Item>
          <Form.Item
            name="profiles"
            label={t('Profiles (comma separated, or all)')}
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
        </Form>
      </Modal>
      {dialog}
    </>
  )
}
export default RequestorList
