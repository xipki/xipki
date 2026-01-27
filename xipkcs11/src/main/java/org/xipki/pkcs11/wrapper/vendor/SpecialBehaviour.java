// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.vendor;

/**
 * @author Lijun Liao (xipki)
 */
public enum SpecialBehaviour {

  ECDH_DER_ECPOINT,

  /**
   * The CKA_EC_PARAMS for CKK_EC_EDWARDS accepts only name instead OID.
   */
  EC_PARAMS_NAME_ONLY_EDWARDS,

  /**
   * The CKA_EC_PARAMS for CKK_EC_EDWARDS accepts only name instead OID.
   */
  EC_PARAMS_NAME_ONLY_MONTGOMERY,

  /**
   * The ECDSA signature is in X9.62 format.
   */
  ECDSA_X962_SIGNATURE,

  /**
   * The SM2 signature is in X9.62 format.
   */
  SM2_X962_SIGNATURE,

  /**
   * The private key of type CKK_EC has the attribute CKA_EC_POINT.
   */
  EC_PRIVATEKEY_ECPOINT,

  /**
   * The private key of type CKK_VENDOR_SM2 has the attribute CKA_EC_POINT.
   */
  SM2_PRIVATEKEY_ECPOINT,

}
