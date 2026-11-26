// License Apache License 2.0


import { useI18n } from '../../i18n'
import { useState } from 'react'
import { Form, Input, Modal, Select } from 'antd'
import { caApi } from '../../api/ca'
import { useReauthentication } from '../../components/Reauthentication'

export default function CaRevoke({
  name,
  onClose,
  onSaved,
}: {
  name: string
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useI18n()
  const { authorize, dialog } = useReauthentication()
  const [form] = Form.useForm()
  const [busy, setBusy] = useState(false)
  async function submit() {
    try {
      const r = await form.validateFields()
      setBusy(true)
      await caApi.revoke(name, r.reason, r.invalidityTime || undefined)
      onSaved()
      onClose()
    } catch {
      /* validation and API client render errors */
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <Modal
        open
        title={t('Revoke CA')}
        onOk={() => {
          void form
            .validateFields()
            .then(() => authorize(t('Revoke CA'), submit))
            .catch(() => {})
        }}
        confirmLoading={busy}
        onCancel={onClose}
      >
        <Form form={form} layout="vertical" initialValues={{ reason: 'unspecified' }}>
          <Form.Item name="reason" label={t('Reason')} rules={[{ required: true }]}>
            <Select
              options={[
                'unspecified',
                'keyCompromise',
                'cACompromise',
                'affiliationChanged',
                'superseded',
                'cessationOfOperation',
                'certificateHold',
                'privilegeWithdrawn',
                'aACompromise',
              ].map((value) => ({ value, label: t(value) }))}
            />
          </Form.Item>
          <Form.Item name="invalidityTime" label={t('Invalidity time (optional UTC)')}>
            <Input placeholder="2026-10-23T00:00:00Z" />
          </Form.Item>
        </Form>
      </Modal>
      {dialog}
    </>
  )
}
