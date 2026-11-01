// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.RSAPublicKey;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.ca.gateway.dns.DnsName;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

/**
 * DNSSEC algorithms. Only the algorithms of RFC 8624 that are not deprecated are
 * supported: 8 RSASHA256, 10 RSASHA512, 13 ECDSAP256SHA256, 14 ECDSAP384SHA384,
 * 15 Ed25519 and 16 Ed448. DS digests: 2 SHA-256 and 4 SHA-384.
 *
 * @author Lijun Liao (xipki)
 */
final class DnssecCrypto {

  static final int RSASHA256 = 8;

  static final int RSASHA512 = 10;

  static final int ECDSAP256SHA256 = 13;

  static final int ECDSAP384SHA384 = 14;

  static final int ED25519 = 15;

  static final int ED448 = 16;

  private static final int MIN_RSA_MODULUS_BITS = 1024;

  private DnssecCrypto() {
  }

  static boolean isSupportedAlgorithm(int alg) {
    return alg == RSASHA256 || alg == RSASHA512 || alg == ECDSAP256SHA256
        || alg == ECDSAP384SHA384 || alg == ED25519 || alg == ED448;
  }

  static boolean isSupportedDigestType(int digestType) {
    return digestType == 2 || digestType == 4;
  }

  /**
   * Computes the DS digest (RFC 4034 section 5.1.4) of the DNSKEY.
   */
  static byte[] dsDigest(int digestType, DnsName owner, byte[] dnskeyRdata) {
    HashAlgo hashAlgo = digestType == 2 ? HashAlgo.SHA256
        : digestType == 4 ? HashAlgo.SHA384 : null;
    if (hashAlgo == null) {
      throw new IllegalArgumentException("unsupported digest type " + digestType);
    }
    return hashAlgo.hash(owner.toWire(), dnskeyRdata);
  }

  /**
   * Verifies the signature.
   *
   * @param alg the DNSSEC algorithm.
   * @param publicKey the public key field of the DNSKEY.
   * @param data the signed data.
   * @param signature the signature field of the RRSIG.
   * @return whether the signature is valid. {@code false} for an invalid key or
   *         signature encoding.
   */
  static boolean verify(int alg, byte[] publicKey, byte[] data, byte[] signature) {
    SignAlgo signAlgo;
    SubjectPublicKeyInfo pkInfo;
    byte[] sig = signature;

    try {
      switch (alg) {
        case RSASHA256:
        case RSASHA512:
          signAlgo = alg == RSASHA256 ? SignAlgo.RSA_SHA256 : SignAlgo.RSA_SHA512;
          pkInfo = rsaPublicKeyInfo(publicKey);
          break;
        case ECDSAP256SHA256:
        case ECDSAP384SHA384: {
          boolean p256 = alg == ECDSAP256SHA256;
          int fieldLen = p256 ? 32 : 48;
          if (publicKey.length != 2 * fieldLen || signature.length != 2 * fieldLen) {
            return false;
          }
          signAlgo = p256 ? SignAlgo.ECDSA_SHA256 : SignAlgo.ECDSA_SHA384;
          byte[] point = new byte[1 + publicKey.length];
          point[0] = 4; // uncompressed
          System.arraycopy(publicKey, 0, point, 1, publicKey.length);
          pkInfo = new SubjectPublicKeyInfo(AlgorithmIdentifier.build(
              AlgorithmOIDs.id_ecPublicKey, p256 ? CurveOIDs.secp256r1 : CurveOIDs.secp384r1),
              point);
          sig = plainToDer(signature, fieldLen);
          break;
        }
        case ED25519:
        case ED448: {
          boolean ed25519 = alg == ED25519;
          if (publicKey.length != (ed25519 ? 32 : 57)) {
            return false;
          }
          signAlgo = ed25519 ? SignAlgo.ED25519 : SignAlgo.ED448;
          pkInfo = new SubjectPublicKeyInfo(AlgorithmIdentifier.build(
              ed25519 ? CurveOIDs.id_ED25519 : CurveOIDs.id_ED448), publicKey);
          break;
        }
        default:
          return false;
      }

      if (pkInfo == null) {
        return false;
      }

      PublicKey key = KeyInfoUtil.getPublicKey(pkInfo);
      Signature verifier = signAlgo.newSignature();
      verifier.initVerify(key);
      verifier.update(data);
      return verifier.verify(sig);
    } catch (GeneralSecurityException | RuntimeException ex) {
      return false;
    }
  }

  /**
   * Converts the RSA public key of RFC 3110 section 2 to SubjectPublicKeyInfo.
   * Returns {@code null} if the encoding is invalid or the modulus is too short.
   */
  private static SubjectPublicKeyInfo rsaPublicKeyInfo(byte[] key) {
    if (key.length < 3) {
      return null;
    }

    int expLen = key[0] & 0xFF;
    int off = 1;
    if (expLen == 0) {
      expLen = ((key[1] & 0xFF) << 8) | (key[2] & 0xFF);
      off = 3;
    }

    if (expLen == 0 || off + expLen >= key.length) {
      return null;
    }

    BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(key, off, off + expLen));
    BigInteger modulus = new BigInteger(1, Arrays.copyOfRange(key, off + expLen, key.length));
    if (modulus.bitLength() < MIN_RSA_MODULUS_BITS) {
      return null;
    }

    return new SubjectPublicKeyInfo(AlgorithmIdentifier.ofNullParams(
        AlgorithmOIDs.id_rsaEncryption), new RSAPublicKey(modulus, exponent).getEncoded());
  }

  /**
   * Converts the ECDSA signature r || s (RFC 6605 section 4) to DER.
   */
  private static byte[] plainToDer(byte[] sig, int fieldLen) {
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, fieldLen));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, fieldLen, 2 * fieldLen));
    return new Asn1Sequence(new Asn1Integer(r), new Asn1Integer(s)).getEncoded();
  }

}
