// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.*;
import org.xipki.util.Args;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.*;

/**
 * Hash algorithm enum.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

//See https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2019/AlgorithmObjectIdentifiers.html
public enum HashAlgo {

  SHA1(20, OIWObjectIdentifiers.idSHA1, "SHA1", true),
  // rfc5754: no parameters
  SHA224(28, id_sha224,  "SHA224"),
  SHA256(32,   id_sha256, "SHA256"),
  SHA384(48,   id_sha384,  "SHA384"),
  SHA512(64,   id_sha512,  "SHA512"),
  SHA3_224(28, id_sha3_224,  "SHA3-224"),
  SHA3_256(32, id_sha3_256,  "SHA3-256"),
  SHA3_384(48, id_sha3_384,  "SHA3-384"),
  SHA3_512(64, id_sha3_512, "SHA3-512"),
  SM3(32, GMObjectIdentifiers.sm3,     "SM3"),

  SHAKE128(32, id_shake128, "SHAKE128"),
  SHAKE256(64, id_shake256, "SHAKE256");

  private static final Map<String, HashAlgo> map = new HashMap<>();

  private final int length;

  private final ASN1ObjectIdentifier oid;

  private final AlgorithmIdentifier algId;

  private final AlgorithmIdentifier algIdWithNullParams;

  private final String jceName;

  private final byte[] encoded;

  static {
    for (HashAlgo type : HashAlgo.values()) {
      map.put(type.oid.getId(), type);
      map.put(type.jceName, type);
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
    map.put("SHAKE128", SHAKE128);
    map.put("SHAKE256", SHAKE256);
  }

  HashAlgo(int length, ASN1ObjectIdentifier oid, String jceName) {
    this(length, oid, jceName, false);
  }

  HashAlgo(int length, ASN1ObjectIdentifier oid, String jceName, boolean withNullParams) {
    this.length = length;
    this.oid = oid;
    if (withNullParams) {
      this.algId = new AlgorithmIdentifier(this.oid, DERNull.INSTANCE);
      this.algIdWithNullParams = this.algId;
    } else {
      this.algId = new AlgorithmIdentifier(this.oid);
      this.algIdWithNullParams = new AlgorithmIdentifier(this.oid, DERNull.INSTANCE);
    }
    this.jceName = jceName;

    try {
      this.encoded = oid.getEncoded();
    } catch (IOException ex) {
      throw new IllegalArgumentException("invalid oid: " + oid);
    }
  }

  public int getLength() {
    return length;
  }

  public ASN1ObjectIdentifier getOid() {
    return oid;
  }

  public String getJceName() {
    return jceName;
  }

  public boolean isShake() {
    return this == SHAKE128 || this == SHAKE256;
  }

  public static HashAlgo getInstance(AlgorithmIdentifier id) throws NoSuchAlgorithmException {
    Args.notNull(id, "id");
    ASN1Encodable params = id.getParameters();
    if (params != null && !DERNull.INSTANCE.equals(params)) {
      throw new NoSuchAlgorithmException("params is present but is not NULL");
    }

    return getInstance(id.getAlgorithm());
  }

  public static HashAlgo getInstance(ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException {
    Args.notNull(oid, "oid");
    for (HashAlgo hashAlgo : values()) {
      if (hashAlgo.oid.equals(oid)) {
        return hashAlgo;
      }
    }
    throw new NoSuchAlgorithmException("Unknown HashAlgo OID '" + oid.getId() + "'");
  }

  public static HashAlgo getInstance(String nameOrOid) throws NoSuchAlgorithmException {
    HashAlgo alg = map.get(nameOrOid.toUpperCase());
    if (alg == null) {
      throw new NoSuchAlgorithmException("Found no HashAlgo for name/OID '" + nameOrOid + "'");
    }
    return alg;
  }

  public static HashAlgo getInstanceForEncoded(byte[] encoded) throws NoSuchAlgorithmException {
    return getInstanceForEncoded(encoded, 0, encoded.length);
  }

  public static HashAlgo getInstanceForEncoded(byte[] encoded, int offset, int len)
      throws NoSuchAlgorithmException {
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
    throw new NoSuchAlgorithmException("Found no HashAlgo for encoded");
  }

  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algId;
  }

  public AlgorithmIdentifier getAlgIdWithNullParams() {
    return algIdWithNullParams;
  }

  public ExtendedDigest createDigest() {
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
      case SHAKE128:
        return new SHAKEDigest(128);
      case SHAKE256:
        return new SHAKEDigest(256);
      default:
        throw new IllegalStateException("should not reach here, unknown HashAlgo " + name());
    }
  }

  public String hexHash(byte[]... datas) {
    return HashCalculator.hexHash(this, datas);
  }

  public String hexHash(byte[] data, int offset, int len) {
    return HashCalculator.hexHash(this, data, offset, len);
  }

  public String base64Hash(byte[]... datas) {
    return HashCalculator.base64Hash(this, datas);
  }

  public String base64Hash(byte[] data, int offset, int len) {
    return HashCalculator.base64Hash(this, data, offset, len);
  }

  public byte[] hash(byte[]... datas) {
    return HashCalculator.hash(this, datas);
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
