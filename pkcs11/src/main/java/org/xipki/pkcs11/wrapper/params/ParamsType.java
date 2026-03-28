// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

/**
 * Params Type enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum ParamsType {

  NullParams(1),
  LongParams(2),
  ByteArrayParams(3),
  GCM_PARAMS(6),
  ECDH1_DERIVE_PARAMS(8),
  EDDSA_PARAMS(11),
  SIGN_ADDITIONAL_CONTEXT(12),
  HASH_SIGN_ADDITIONAL_CONTEXT(13),
  RSA_PKCS_OAEP_PARAMS(18),
  RSA_PKCS_PSS_PARAMS(19),
  XEDDSA_PARAMS(27);

  private final byte code;

  ParamsType(int code) {
    this.code = (byte) code;
  }

  public byte getCode() {
    return code;
  }

  public static ParamsType ofCode(byte code) {
    for (ParamsType v : ParamsType.values()) {
      if (v.code == code) {
        return v;
      }
    }
    return null;
  }

}
