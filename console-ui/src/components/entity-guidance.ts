// License Apache License 2.0


export type EntityResource = 'SIGNER' | 'REQUESTOR' | 'PUBLISHER' | 'KEYPAIRGEN'

interface TypeGuide {
  description: string
  example: string
  note: string
}
interface ResourceGuide {
  usage: string
  nameExample: string
  supportedTypeKey?: 'signerTypes' | 'publisherTypes'
  typeOptions?: string[]
  types: Record<string, TypeGuide>
}

// Examples explain syntax; the CA supplies the available plugin types.
export const entityGuidance: Partial<Record<EntityResource, ResourceGuide>> = {
  SIGNER: {
    usage: 'Signer usage guidance',
    nameExample: 'crl-signer',
    supportedTypeKey: 'signerTypes',
    types: {
      pkcs12: {
        description: 'PKCS12 signer type description',
        example:
          'algo=SHA256withRSA,parallelism=2,password=CHANGE_ME,keystore=file:/data/keys/signer.p12,key-label=signer',
        note: 'File signer example guidance',
      },
      jceks: {
        description: 'JCEKS signer type description',
        example:
          'algo=SHA256withRSA,parallelism=2,password=CHANGE_ME,keystore=file:/data/keys/signer.jceks,key-label=signer',
        note: 'File signer example guidance',
      },
      pkcs11: {
        description: 'PKCS11 signer type description',
        example: 'algo=SHA256withRSA,parallelism=2,module=default,slot=0,key-label=crl-signer',
        note: 'Hardware signer example guidance',
      },
    },
  },
  REQUESTOR: {
    usage: 'Requestor usage guidance',
    nameExample: 'cmp-client',
    typeOptions: ['cert'],
    types: {
      cert: {
        description: 'Certificate requestor type description',
        example: 'MIIC...BASE64_OF_COMPLETE_DER_CERTIFICATE...==',
        note: 'Certificate requestor example guidance',
      },
    },
  },
  PUBLISHER: {
    usage: 'Publisher usage guidance',
    nameExample: 'ocsp-publisher',
    supportedTypeKey: 'publisherTypes',
    types: {
      ocsp: {
        description: 'OCSP publisher type description',
        example: 'datasource=YOUR_OCSP_DATASOURCE,publish.goodcerts=true',
        note: 'OCSP publisher example guidance',
      },
    },
  },
}
