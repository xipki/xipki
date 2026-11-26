// License Apache License 2.0


import { useEffect, useRef, useState } from 'react'
import { Alert, Input, Modal } from 'antd'
import api from '../api/client'
import { useI18n } from '../i18n'

export function useReauthentication(resource?: string) {
  const { t } = useI18n()
  const [operation, setOperation] = useState<{
    title: string
    id: number
    resource?: string
    run: () => Promise<void>
  }>()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const identity = useRef(resource)
  identity.current = resource
  const serial = useRef(0)
  const pending = useRef<number>()
  useEffect(() => {
    setPassword('')
    setOperation(undefined)
    setBusy(false)
    pending.current = undefined
    return () => {
      serial.current++
    }
  }, [resource])
  const authorize = (title: string, run: () => Promise<void>) => {
    setPassword('')
    setBusy(false)
    pending.current = undefined
    setOperation({ title, id: ++serial.current, resource, run })
  }
  const submit = async () => {
    if (
      !operation ||
      busy ||
      !password ||
      pending.current !== undefined ||
      operation.resource !== identity.current
    )
      return
    const current = () => serial.current === operation.id && operation.resource === identity.current
    pending.current = operation.id
    setBusy(true)
    try {
      await api.post('/api/auth/reauth', { password })
      if (!current()) return
      setPassword('')
      setOperation(undefined)
      await operation.run()
    } catch {
      /* The API client reports failure; mutations are never replayed. */
    } finally {
      if (current()) {
        pending.current = undefined
        setPassword('')
        setBusy(false)
      }
    }
  }
  return {
    authorize,
    dialog: (
      <Modal
        title={operation?.title}
        open={!!operation}
        confirmLoading={busy}
        okText={t('Verify and continue')}
        cancelText={t('Cancel')}
        okButtonProps={{ disabled: !password }}
        onOk={() => void submit()}
        closable={!busy}
        maskClosable={!busy}
        onCancel={() => {
          if (!busy) {
            serial.current++
            setPassword('')
            setOperation(undefined)
          }
        }}
      >
        <Alert
          type="info"
          showIcon
          message={t('Enter your current password to confirm this sensitive operation.')}
          style={{ marginBottom: 16 }}
        />
        <Input.Password
          aria-label={t('Current password')}
          autoComplete="current-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          onPressEnter={() => void submit()}
          disabled={busy}
        />
      </Modal>
    ),
  }
}
