// License Apache License 2.0


import { useI18n } from '../../i18n'
import React from 'react'
import EntityCrudPage from '../../components/EntityCrudPage'
import { keypairGenApi } from '../../api/entities'

const KeypairGenList: React.FC = () => {
  const { t } = useI18n()
  return (
    <EntityCrudPage resource="KEYPAIRGEN" title={t('Keypair Generators')} api={keypairGenApi} />
  )
}

export default KeypairGenList
