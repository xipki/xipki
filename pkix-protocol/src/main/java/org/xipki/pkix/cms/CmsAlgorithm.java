// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cms;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.asn1.oid.SecOIDs;
import org.xipki.codec.asn1.oid.X9OIDs;

/**
 * The CMS algorithms supported by XiPKI.
 *
 * @author Lijun Liao (xipki)
 */
public final class CmsAlgorithm {

  // content encryption, and key encryption of the password recipient (RFC 3211)
  public static final Asn1Oid DES_EDE3_CBC   = PkcsOIDs.des_EDE3_CBC;
  public static final Asn1Oid AES128_CBC     = NistOIDs.id_aes128_CBC;
  public static final Asn1Oid AES192_CBC     = NistOIDs.id_aes192_CBC;
  public static final Asn1Oid AES256_CBC     = NistOIDs.id_aes256_CBC;

  // content encryption
  public static final Asn1Oid AES128_GCM     = NistOIDs.id_aes128_GCM;
  public static final Asn1Oid AES192_GCM     = NistOIDs.id_aes192_GCM;
  public static final Asn1Oid AES256_GCM     = NistOIDs.id_aes256_GCM;

  // key wrap of the key agreement recipient
  public static final Asn1Oid AES128_WRAP    = NistOIDs.id_aes128_wrap;
  public static final Asn1Oid AES192_WRAP    = NistOIDs.id_aes192_wrap;
  public static final Asn1Oid AES256_WRAP    = NistOIDs.id_aes256_wrap;

  // key agreement
  public static final Asn1Oid ECDH_SHA1KDF   = X9OIDs.dhSinglePass_stdDH_sha1kdf_scheme;
  public static final Asn1Oid ECDH_SHA224KDF = SecOIDs.dhSinglePass_stdDH_sha224kdf_scheme;
  public static final Asn1Oid ECDH_SHA256KDF = SecOIDs.dhSinglePass_stdDH_sha256kdf_scheme;
  public static final Asn1Oid ECDH_SHA384KDF = SecOIDs.dhSinglePass_stdDH_sha384kdf_scheme;
  public static final Asn1Oid ECDH_SHA512KDF = SecOIDs.dhSinglePass_stdDH_sha512kdf_scheme;

  // key transport
  public static final Asn1Oid RSA_PKCS15     = PkcsOIDs.rsaEncryption;
  public static final Asn1Oid RSA_OAEP       = PkcsOIDs.id_RSAES_OAEP;

  private CmsAlgorithm() {
  }

}
