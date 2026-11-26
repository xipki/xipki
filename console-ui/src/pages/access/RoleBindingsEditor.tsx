// License Apache License 2.0


import { useEffect, useState } from 'react'
import { Alert, Button, Checkbox, Collapse, Modal, Select, Space, Typography, message } from 'antd'
import api from '../../api/client'
import type { Binding } from '../../access-policy'
import type { Role } from './Roles'
import { useI18n } from '../../i18n'
import { useReauthentication } from '../../components/Reauthentication'
import PermissionSummary from './PermissionSummary'
import type { Permission } from './roles-model'

type CaOption = { name: string; fingerprint: string; profiles: string[] }
type Target = { id: number; username: string; bindings: Binding[] }
export default function RoleBindingsEditor({
  target,
  onClose,
  onSaved,
}: {
  target: Target
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useI18n()
  const { authorize, dialog } = useReauthentication()
  const [roles, setRoles] = useState<Role[]>([])
  const [catalog, setCatalog] = useState<Permission[]>([])
  const [activeGrant, setActiveGrant] = useState<string | undefined>('0')
  const [cas, setCas] = useState<CaOption[]>([])
  const [bindings, setBindings] = useState<Binding[]>(
    target.bindings.map((binding) => ({ ...binding, profiles: [...binding.profiles] })),
  )
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [saving, setSaving] = useState(false)
  const [allConfirmed, setAllConfirmed] = useState(false)
  useEffect(() => {
    let active = true
    Promise.all([
      api.get('/api/roles'),
      api.get('/api/access-options'),
      api.get('/api/permissions'),
    ])
      .then(([roleResponse, caResponse, permissionResponse]) => {
        if (active) {
          setRoles(roleResponse.data.data)
          setCas(caResponse.data.data)
          setCatalog(permissionResponse.data.data)
        }
      })
      .catch(() => {
        if (active) setFailed(true)
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [])
  const update = (index: number, value: Partial<Binding>) => {
    setBindings((current) =>
      current.map((binding, i) => (i === index ? { ...binding, ...value } : binding)),
    )
    setAllConfirmed(false)
  }
  const hasAll = bindings.some((binding) => binding.scope === 'ALL_CAS' || binding.allProfiles)
  const valid =
    !failed &&
    !loading &&
    bindings.every(
      (binding) =>
        binding.role &&
        (roles.some((role) => role.name === binding.role && role.enabled) ||
          target.bindings.some((old) => old.role === binding.role)) &&
        (binding.scope !== 'NAMED_CA' ||
          cas.some((ca) => ca.name === binding.caName && ca.fingerprint === binding.caFingerprint)),
    ) &&
    (!hasAll || allConfirmed)
  const save = () => {
    if (!valid || saving) return
    authorize(t('Save role grants for {name}', { name: target.username }), async () => {
      setSaving(true)
      try {
        await api.put(`/api/users/${target.id}/role-bindings`, {
          bindings: bindings.map((binding) => ({
            role: binding.role,
            scope: binding.scope,
            ...(binding.scope === 'NAMED_CA'
              ? { caName: binding.caName, caFingerprint: binding.caFingerprint }
              : {}),
            allProfiles: binding.allProfiles === true,
            profiles: binding.profiles,
          })),
        })
        message.success(t('Role grants saved. Existing sessions have been revoked.'))
        onSaved()
        onClose()
      } finally {
        setSaving(false)
      }
    })
  }
  return (
    <>
      <Modal
        title={t('Role grants for {name}', { name: target.username })}
        open
        width={1000}
        className="access-modal"
        style={{ top: 24 }}
        onCancel={() => !saving && onClose()}
        onOk={save}
        confirmLoading={saving}
        okButtonProps={{ disabled: !valid }}
        okText={t('Save grants')}
      >
        <Alert
          type="info"
          showIcon
          message={t(
            'Each grant combines one role with its own resource scope. An empty list grants no access.',
          )}
          style={{ marginBottom: 16 }}
        />
        {failed && (
          <Alert
            type="error"
            message={t('Could not load authorization options. Close and retry.')}
          />
        )}
        <Space direction="vertical" style={{ width: '100%' }}>
          <Typography.Text type="secondary">
            {t('{count} role grants', { count: bindings.length })}
          </Typography.Text>
          <Collapse
            className="access-grants"
            accordion
            activeKey={activeGrant}
            onChange={(key) => setActiveGrant(Array.isArray(key) ? key[0] : key)}
            items={bindings.map((binding, index) => {
              const definition = roles.find((role) => role.name === binding.role)
              const platform = definition?.scope === 'PLATFORM'
              const ca = cas.find((item) => item.name === binding.caName)
              const stale =
                binding.scope === 'NAMED_CA' &&
                !!(binding.caName || binding.caFingerprint) &&
                (!ca || ca.fingerprint !== binding.caFingerprint)
              const profiles =
                binding.scope === 'NAMED_CA'
                  ? ca?.profiles || []
                  : [...new Set(cas.flatMap((item) => item.profiles))]
              return {
                key: String(index),
                label: (
                  <Space wrap>
                    <strong>{t('Grant {number}', { number: index + 1 })}</strong>
                    <span>{definition ? t(definition.displayName) : t('Select role')}</span>
                    <Typography.Text type="secondary">
                      {platform
                        ? t('Platform')
                        : binding.scope === 'ALL_CAS'
                          ? t('All current and future CAs')
                          : binding.caName || t('Select CA')}
                    </Typography.Text>
                    {stale && (
                      <Typography.Text type="warning">{t('Inactive grant')}</Typography.Text>
                    )}
                  </Space>
                ),
                extra: (
                  <Button
                    danger
                    size="small"
                    onClick={(event) => {
                      event.stopPropagation()
                      setBindings(bindings.filter((_, i) => i !== index))
                      setActiveGrant(undefined)
                      setAllConfirmed(false)
                    }}
                    disabled={saving}
                  >
                    {t('Remove')}
                  </Button>
                ),
                children: (
                  <Space direction="vertical" style={{ width: '100%' }}>
                    <Select
                      aria-label={t('Role')}
                      showSearch
                      optionFilterProp="label"
                      style={{ width: '100%' }}
                      value={binding.role || undefined}
                      placeholder={t('Select role')}
                      loading={loading}
                      disabled={saving}
                      options={roles.map((role) => ({
                        value: role.name,
                        label: `${t(role.displayName)} (${role.name})${role.enabled ? '' : ` — ${t('Disabled')}`}`,
                        disabled: !role.enabled,
                      }))}
                      onChange={(role) => {
                        const scope =
                          roles.find((item) => item.name === role)?.scope === 'PLATFORM'
                            ? 'PLATFORM'
                            : 'NAMED_CA'
                        update(index, {
                          role,
                          scope,
                          caName: null,
                          caFingerprint: null,
                          profiles: [],
                          allProfiles: false,
                        })
                      }}
                    />
                    {definition && !definition.enabled && (
                      <Alert
                        type="warning"
                        message={t(
                          'This role is disabled. Its grants provide no permissions until it is enabled.',
                        )}
                      />
                    )}
                    {definition &&
                      (definition.enabled ? (
                        <PermissionSummary
                          permissions={definition.permissions}
                          catalog={catalog}
                          title={`${t(definition.displayName)} · ${t('Effective actions')}`}
                        />
                      ) : (
                        <Typography.Text type="secondary">
                          {t('Effective actions')}: {t('None')}
                        </Typography.Text>
                      ))}
                    {platform ? (
                      <TagScope text={t('Platform')} />
                    ) : (
                      <>
                        <Select
                          aria-label={t('Scope')}
                          style={{ width: '100%' }}
                          value={binding.scope}
                          disabled={saving}
                          options={[
                            { value: 'NAMED_CA', label: t('Specific CA') },
                            { value: 'ALL_CAS', label: t('All current and future CAs') },
                          ]}
                          onChange={(scope) =>
                            update(index, {
                              scope,
                              caName: null,
                              caFingerprint: null,
                              profiles: [],
                              allProfiles: false,
                            })
                          }
                        />
                        {binding.scope === 'NAMED_CA' && (
                          <Select
                            aria-label={t('CA')}
                            showSearch
                            optionFilterProp="value"
                            style={{ width: '100%' }}
                            value={binding.caName || undefined}
                            placeholder={t('Select CA')}
                            options={cas.map((item) => ({ value: item.name }))}
                            disabled={saving}
                            onChange={(name) => {
                              const selected = cas.find((item) => item.name === name)!
                              update(index, {
                                caName: name,
                                caFingerprint: selected.fingerprint,
                                profiles: [],
                              })
                            }}
                          />
                        )}
                        {binding.caFingerprint && (
                          <Typography.Text type="secondary" style={{ wordBreak: 'break-all' }}>
                            {t('CA certificate fingerprint')}: {binding.caFingerprint}
                          </Typography.Text>
                        )}
                        {stale && (
                          <Alert
                            type="warning"
                            showIcon
                            message={t(
                              'The CA is missing or its identity has changed. This grant is inactive. Review and explicitly rebind before saving.',
                            )}
                            action={
                              ca && (
                                <Button
                                  onClick={() => update(index, { caFingerprint: ca.fingerprint })}
                                >
                                  {t('Rebind to current CA identity')}
                                </Button>
                              )
                            }
                          />
                        )}
                        {(definition?.needsProfiles ||
                          binding.allProfiles ||
                          binding.profiles.length > 0) && (
                          <>
                            <Checkbox
                              checked={binding.allProfiles}
                              disabled={saving}
                              onChange={(event) =>
                                update(index, { allProfiles: event.target.checked, profiles: [] })
                              }
                            >
                              {t('All certificate profiles')}
                            </Checkbox>
                            {!binding.allProfiles && (
                              <Select
                                aria-label={t('Allowed profiles')}
                                mode="multiple"
                                style={{ width: '100%' }}
                                placeholder={t('Select allowed profiles')}
                                value={binding.profiles}
                                options={profiles.map((value) => ({ value }))}
                                disabled={saving}
                                onChange={(values) => update(index, { profiles: values })}
                              />
                            )}
                            {!binding.allProfiles && !binding.profiles.length && (
                              <Typography.Text type="warning">
                                {t('No profiles selected: certificate issuance is denied.')}
                              </Typography.Text>
                            )}
                          </>
                        )}
                      </>
                    )}
                  </Space>
                ),
              }
            })}
          />
          <Button
            onClick={() => {
              setActiveGrant(String(bindings.length))
              setBindings([
                ...bindings,
                { role: '', scope: 'NAMED_CA', allProfiles: false, profiles: [] },
              ])
            }}
            disabled={saving || loading || failed || bindings.length >= 100}
          >
            {t('Add role grant')}
          </Button>
          {hasAll && (
            <Alert
              type="warning"
              showIcon
              message={t(
                'All scopes include future resources and replacement CAs. Grant only to trusted users.',
              )}
              description={
                <Checkbox
                  checked={allConfirmed}
                  onChange={(event) => setAllConfirmed(event.target.checked)}
                >
                  {t('I confirm the unrestricted resource scopes above')}
                </Checkbox>
              }
            />
          )}
          <Typography.Paragraph type="secondary">
            {t(
              'Audit permissions cannot be combined with write permissions. User administrators cannot grant roles or maintain privileged accounts.',
            )}
          </Typography.Paragraph>
        </Space>
      </Modal>
      {dialog}
    </>
  )
}

function TagScope({ text }: { text: string }) {
  return <Typography.Text type="secondary">{text}</Typography.Text>
}
