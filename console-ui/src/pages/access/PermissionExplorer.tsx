// License Apache License 2.0


import { useState } from 'react'
import { Checkbox, Empty, Input, Space, Tag, Tooltip, Typography } from 'antd'
import { useI18n } from '../../i18n'
import type { Permission } from './roles-model'
import './access.css'

/** Catalog-driven browsing shared by role editing and read-only permission details. */
export default function PermissionExplorer({
  catalog,
  selected,
  onToggle,
  disabled = false,
}: {
  catalog: Permission[]
  selected: string[]
  onToggle?: (code: string, checked: boolean) => void
  disabled?: boolean
}) {
  const { t } = useI18n()
  const [search, setSearch] = useState('')
  const [selectedOnly, setSelectedOnly] = useState(!onToggle)
  const [active, setActive] = useState('')
  const query = search.trim().toLowerCase()
  const groups = [...new Set(catalog.map((item) => item.group))]
  const matches = catalog.filter(
    (item) =>
      (!selectedOnly || selected.includes(item.code)) &&
      [item.code, t(item.code), item.group, t(item.group)].some((value) =>
        value.toLowerCase().includes(query),
      ),
  )
  const visibleGroups = groups.filter((group) => matches.some((item) => item.group === group))
  const current = visibleGroups.includes(active) ? active : visibleGroups[0]
  return (
    <div className="permission-explorer">
      <div className="permission-toolbar">
        <Input.Search
          aria-label={t('Search permissions')}
          placeholder={t('Search permissions')}
          allowClear
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        {onToggle && (
          <Checkbox
            checked={selectedOnly}
            onChange={(event) => setSelectedOnly(event.target.checked)}
          >
            {t('Selected only')}
          </Checkbox>
        )}
        <Typography.Text type="secondary">
          {t('{count} permissions selected', { count: selected.length })}
        </Typography.Text>
      </div>
      <div className="permission-browser">
        <nav className="permission-navigation" aria-label={t('Permission groups')}>
          {visibleGroups.map((group) => (
            <button
              type="button"
              key={group}
              data-permission-group={group}
              aria-current={current === group ? 'true' : undefined}
              onClick={() => setActive(group)}
            >
              <span>{t(group)}</span>
              <span className="permission-group-count">
                {
                  catalog.filter((item) => item.group === group && selected.includes(item.code))
                    .length
                }
                /{catalog.filter((item) => item.group === group).length}
              </span>
            </button>
          ))}
        </nav>
        <section className="permission-content" aria-label={t('Permissions')}>
          {current ? (
            <>
              <div className="permission-group-heading">
                <Typography.Title level={5}>{t(current)}</Typography.Title>
                <Typography.Text type="secondary">
                  {t('{count} matching permissions', {
                    count: matches.filter((item) => item.group === current).length,
                  })}
                </Typography.Text>
              </div>
              {matches
                .filter((item) => item.group === current)
                .map((item) => (
                  <div className="permission-row" key={item.code}>
                    <div>
                      <Tooltip title={item.code}>
                        {onToggle ? (
                          <Checkbox
                            data-permission={item.code}
                            checked={selected.includes(item.code)}
                            disabled={disabled || item.reserved}
                            onChange={(event) => onToggle(item.code, event.target.checked)}
                          >
                            {t(item.code)}
                          </Checkbox>
                        ) : (
                          <Typography.Text>{t(item.code)}</Typography.Text>
                        )}
                      </Tooltip>
                    </div>
                    <div className="permission-conditions">
                      {(item.reserved ||
                        item.highRisk ||
                        item.allCasOnly ||
                        item.profileRequired) && (
                        <Space size={[0, 4]} wrap>
                          {item.reserved && <Tag>{t('Super administrator only')}</Tag>}
                          {item.highRisk && !item.reserved && (
                            <Tag color="red">{t('High risk')}</Tag>
                          )}
                          {item.allCasOnly && <Tag>{t('Requires all CA scope')}</Tag>}
                          {item.profileRequired && <Tag>{t('Requires profile grants')}</Tag>}
                        </Space>
                      )}
                      {!!item.dependencies.length && (
                        <div>
                          <Typography.Text type="secondary">
                            {t('Required permissions')}:{' '}
                            {item.dependencies.map((code) => t(code)).join(', ')}
                          </Typography.Text>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
            </>
          ) : (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description={t('No matching permissions')}
            />
          )}
        </section>
      </div>
    </div>
  )
}
