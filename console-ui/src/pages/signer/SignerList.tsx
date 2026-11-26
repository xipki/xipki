// License Apache License 2.0


import { useI18n } from '../../i18n'
import React from 'react'
import EntityCrudPage from '../../components/EntityCrudPage'
import { signerApi } from '../../api/entities'

const SignerList: React.FC = () => {
  const { t } = useI18n()
  return <EntityCrudPage resource="SIGNER" title={t('Signers')} api={signerApi} showBase64Cert />
}

export default SignerList
