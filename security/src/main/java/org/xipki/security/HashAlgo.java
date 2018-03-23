/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.xipki.common.util.ParamUtil;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum HashAlgo {

  SHA1(20, AlgorithmCode.SHA1, "1.3.14.3.2.26", "SHA1"),
  SHA224(28, AlgorithmCode.SHA224, "2.16.840.1.101.3.4.2.4", "SHA224"),
  SHA256(32, AlgorithmCode.SHA256, "2.16.840.1.101.3.4.2.1", "SHA256"),
  SHA384(48, AlgorithmCode.SHA384, "2.16.840.1.101.3.4.2.2", "SHA384"),
  SHA512(64, AlgorithmCode.SHA512, "2.16.840.1.101.3.4.2.3", "SHA512"),
  SHA3_224(28, AlgorithmCode.SHA3_224, "2.16.840.1.101.3.4.2.7", "SHA3-224"),
  SHA3_256(32, AlgorithmCode.SHA3_256, "2.16.840.1.101.3.4.2.8", "SHA3-256"),
  SHA3_384(48, AlgorithmCode.SHA3_384, "2.16.840.1.101.3.4.2.9", "SHA3-384"),
  SHA3_512(64, AlgorithmCode.SHA3_512, "2.16.840.1.101.3.4.2.10", "SHA3-512"),
  SM3(32, AlgorithmCode.SM3, "1.2.156.10197.1.401", "SM3");

  private static final Map<String, HashAlgo> map = new HashMap<>();

  private final int length;

  private final ASN1ObjectIdentifier oid;

  private final AlgorithmIdentifier algId;

  private final String name;

  private final AlgorithmCode algorithmCode;

  private final byte[] encoded;

  static {
    for (HashAlgo type : HashAlgo.values()) {
      map.put(type.oid.getId(), type);
      map.put(type.name, type);
    }

    map.put("SHA-1",   SHA1);
    map.put("SHA-224", SHA224);
    map.put("SHA-256", SHA256);
    map.put("SHA-384", SHA384);
    map.put("SHA-512", SHA512);
    map.put("SHA3224", SHA3_224);
    map.put("SHA3256", SHA3_256);
    map.put("SHA3384", SHA3_384);
    map.put("SHA3512", SHA3_512);
  }

  private HashAlgo(int length, AlgorithmCode algorithmCode, String oid, String name) {
    this.length = length;
    this.algorithmCode = algorithmCode;
    this.oid = new ASN1ObjectIdentifier(oid).intern();
    this.algId = new AlgorithmIdentifier(this.oid, DERNull.INSTANCE);
    this.name = name;

    try {
      this.encoded = new ASN1ObjectIdentifier(oid).getEncoded();
    } catch (IOException ex) {
      throw new IllegalArgumentException("invalid oid: " + oid);
    }
  }

  public int getLength() {
    return length;
  }

  public AlgorithmCode getAlgorithmCode() {
    return algorithmCode;
  }

  public ASN1ObjectIdentifier getOid() {
    return oid;
  }

  public String getName() {
    return name;
  }

  public static HashAlgo getInstance(ASN1ObjectIdentifier oid) {
    ParamUtil.requireNonNull("oid", oid);
    for (HashAlgo hashAlgo : values()) {
      if (hashAlgo.oid.equals(oid)) {
        return hashAlgo;
      }
    }
    return null;
  }

  public static HashAlgo getInstance(String nameOrOid) {
    return map.get(nameOrOid.toUpperCase());
  }

  public static HashAlgo getNonNullInstance(ASN1ObjectIdentifier oid) {
    HashAlgo type = getInstance(oid);
    if (type == null) {
      throw new IllegalArgumentException("Unknown HashAlgo OID '" + oid.getId() + "'");
    }
    return type;
  }

  public static HashAlgo getNonNullInstance(String nameOrOid) {
    HashAlgo type = getInstance(nameOrOid);
    if (type == null) {
      throw new IllegalArgumentException("Unknown HashAlgo OID/name '" + nameOrOid + "'");
    }
    return type;
  }

  public static HashAlgo getInstanceForPkcs11HashMech(long hashMech) {
    if (hashMech == PKCS11Constants.CKM_SHA_1) {
      return HashAlgo.SHA1;
    } else if (hashMech == PKCS11Constants.CKM_SHA224) {
      return HashAlgo.SHA224;
    } else if (hashMech == PKCS11Constants.CKM_SHA256) {
      return HashAlgo.SHA256;
    } else if (hashMech == PKCS11Constants.CKM_SHA384) {
      return HashAlgo.SHA384;
    } else if (hashMech == PKCS11Constants.CKM_SHA512) {
      return HashAlgo.SHA512;
    } else if (hashMech == PKCS11Constants.CKM_SHA3_224) {
      return HashAlgo.SHA3_224;
    } else if (hashMech == PKCS11Constants.CKM_SHA3_256) {
      return HashAlgo.SHA3_256;
    } else if (hashMech == PKCS11Constants.CKM_SHA3_384) {
      return HashAlgo.SHA3_384;
    } else if (hashMech == PKCS11Constants.CKM_SHA3_512) {
      return HashAlgo.SHA3_512;
    } else if (hashMech == PKCS11Constants.CKM_VENDOR_SM3) {
      return HashAlgo.SM3;
    } else {
      return null;
    }
  }

  public static HashAlgo getInstanceForPkcs11MgfMech(long hashMech) {
    if (hashMech == PKCS11Constants.CKG_MGF1_SHA1) {
      return HashAlgo.SHA1;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA224) {
      return HashAlgo.SHA224;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA256) {
      return HashAlgo.SHA256;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA384) {
      return HashAlgo.SHA384;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA512) {
      return HashAlgo.SHA512;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_224) {
      return HashAlgo.SHA3_224;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_256) {
      return HashAlgo.SHA3_256;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_384) {
      return HashAlgo.SHA3_384;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_512) {
      return HashAlgo.SHA3_512;
    } else {
      // SM3 does not apply to RSAPSS signature
      return null;
    }
  }

  public static HashAlgo getInstanceForEncoded(byte[] encoded) {
    return getInstanceForEncoded(encoded, 0, encoded.length);
  }

  public static HashAlgo getInstanceForEncoded(byte[] encoded, int offset, int len) {
    for (HashAlgo value : values()) {
      byte[] ve = value.encoded;
      if (ve.length != len) {
        continue;
      }

      boolean equals = true;
      for (int i = 0; i < len; i++) {
        if (ve[i] != encoded[offset + i]) {
          equals = false;
          break;
        }
      }

      if (equals) {
        return value;
      }
    }
    return null;
  }

  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algId;
  }

  public Digest createDigest() {
    switch (this) {
      case SHA1:
        return new SHA1Digest();
      case SHA224:
        return new SHA224Digest();
      case SHA256:
        return new SHA256Digest();
      case SHA384:
        return new SHA384Digest();
      case SHA512:
        return new SHA512Digest();
      case SHA3_224:
        return new SHA3Digest(224);
      case SHA3_256:
        return new SHA3Digest(256);
      case SHA3_384:
        return new SHA3Digest(384);
      case SHA3_512:
        return new SHA3Digest(512);
      case SM3:
        return new SM3Digest();
      default:
        throw new RuntimeException("should not reach here, unknown HashAlgo " + name());
    }
  }

  public String hexHash(byte[] data) {
    return HashCalculator.hexHash(this, data);
  }

  public String hexHash(byte[] data, int offset, int len) {
    return HashCalculator.hexHash(this, data, offset, len);
  }

  public String base64Hash(byte[] data) {
    return HashCalculator.base64Hash(this, data);
  }

  public String base64Hash(byte[] data, int offset, int len) {
    return HashCalculator.base64Hash(this, data, offset, len);
  }

  public byte[] hash(byte[] data) {
    return HashCalculator.hash(this, data);
  }

  public byte[] hash(byte[] data, int offset, int len) {
    return HashCalculator.hash(this, data, offset, len);
  }

  public int getEncodedLength() {
    return encoded.length;
  }

  public int write(byte[] out, int offset) {
    System.arraycopy(encoded, 0, out, offset, encoded.length);
    return encoded.length;
  }
}
