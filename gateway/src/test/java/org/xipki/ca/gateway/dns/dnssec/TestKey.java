// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns.dnssec;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

/**
 * DNSSEC key pair for tests, generated with the JDK.
 *
 * @author Lijun Liao (xipki)
 */
final class TestKey {

  static final int FLAGS_ZSK = 256;

  static final int FLAGS_KSK = 257;

  final int algorithm;

  final KeyPair keyPair;

  byte[] publicKey;

  int flags;

  int protocol = 3;

  TestKey(int algorithm, int flags, KeyPair keyPair) {
    this.algorithm = algorithm;
    this.flags = flags;
    this.keyPair = keyPair;
    this.publicKey = encodePublicKey();
  }

  static KeyPair generate(int algorithm) throws GeneralSecurityException {
    KeyPairGenerator kpg;
    switch (algorithm) {
      case DnssecCrypto.RSASHA256:
      case DnssecCrypto.RSASHA512:
        kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        break;
      case DnssecCrypto.ECDSAP256SHA256:
      case DnssecCrypto.ECDSAP384SHA384:
        kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(
            algorithm == DnssecCrypto.ECDSAP256SHA256 ? "secp256r1" : "secp384r1"));
        break;
      case DnssecCrypto.ED25519:
        kpg = KeyPairGenerator.getInstance("Ed25519");
        break;
      case DnssecCrypto.ED448:
        kpg = KeyPairGenerator.getInstance("Ed448");
        break;
      default:
        throw new IllegalArgumentException("unsupported algorithm " + algorithm);
    }
    return kpg.generateKeyPair();
  }

  private byte[] encodePublicKey() {
    switch (algorithm) {
      case DnssecCrypto.RSASHA256:
      case DnssecCrypto.RSASHA512: {
        RSAPublicKey pk = (RSAPublicKey) keyPair.getPublic();
        byte[] e = unsigned(pk.getPublicExponent());
        byte[] n = unsigned(pk.getModulus());
        byte[] ret = new byte[1 + e.length + n.length];
        ret[0] = (byte) e.length;
        System.arraycopy(e, 0, ret, 1, e.length);
        System.arraycopy(n, 0, ret, 1 + e.length, n.length);
        return ret;
      }
      case DnssecCrypto.ECDSAP256SHA256:
      case DnssecCrypto.ECDSAP384SHA384: {
        int len = fieldLen();
        ECPublicKey pk = (ECPublicKey) keyPair.getPublic();
        byte[] ret = new byte[2 * len];
        copyFixed(pk.getW().getAffineX(), ret, 0, len);
        copyFixed(pk.getW().getAffineY(), ret, len, len);
        return ret;
      }
      default: {
        // Ed25519 / Ed448: the raw key is at the end of the SubjectPublicKeyInfo
        byte[] encoded = keyPair.getPublic().getEncoded();
        int len = algorithm == DnssecCrypto.ED25519 ? 32 : 57;
        return Arrays.copyOfRange(encoded, encoded.length - len, encoded.length);
      }
    }
  }

  private int fieldLen() {
    return algorithm == DnssecCrypto.ECDSAP256SHA256 ? 32 : 48;
  }

  byte[] dnskeyRdata() {
    byte[] rdata = new byte[4 + publicKey.length];
    rdata[0] = (byte) (flags >>> 8);
    rdata[1] = (byte) flags;
    rdata[2] = (byte) protocol;
    rdata[3] = (byte) algorithm;
    System.arraycopy(publicKey, 0, rdata, 4, publicKey.length);
    return rdata;
  }

  int keyTag() {
    return DnssecValidator.Dnskey.keyTag(dnskeyRdata());
  }

  byte[] sign(byte[] data) throws GeneralSecurityException {
    String name;
    switch (algorithm) {
      case DnssecCrypto.RSASHA256:
        name = "SHA256withRSA";
        break;
      case DnssecCrypto.RSASHA512:
        name = "SHA512withRSA";
        break;
      case DnssecCrypto.ECDSAP256SHA256:
        name = "SHA256withECDSA";
        break;
      case DnssecCrypto.ECDSAP384SHA384:
        name = "SHA384withECDSA";
        break;
      case DnssecCrypto.ED25519:
        name = "Ed25519";
        break;
      default:
        name = "Ed448";
    }

    Signature signer = Signature.getInstance(name);
    signer.initSign(keyPair.getPrivate());
    signer.update(data);
    byte[] sig = signer.sign();
    if (algorithm == DnssecCrypto.ECDSAP256SHA256
        || algorithm == DnssecCrypto.ECDSAP384SHA384) {
      sig = derToPlain(sig, fieldLen());
    }
    return sig;
  }

  private static byte[] derToPlain(byte[] der, int len) {
    // SEQUENCE { INTEGER r, INTEGER s }, short form lengths for P-256 and P-384
    int off = (der[1] & 0x80) != 0 ? 3 : 2;
    byte[] ret = new byte[2 * len];
    for (int i = 0; i < 2; i++) {
      int intLen = der[off + 1] & 0xFF;
      BigInteger v = new BigInteger(Arrays.copyOfRange(der, off + 2, off + 2 + intLen));
      copyFixed(v, ret, i * len, len);
      off += 2 + intLen;
    }
    return ret;
  }

  private static byte[] unsigned(BigInteger v) {
    byte[] b = v.toByteArray();
    return b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b;
  }

  private static void copyFixed(BigInteger v, byte[] dest, int off, int len) {
    byte[] b = unsigned(v);
    System.arraycopy(b, 0, dest, off + len - b.length, b.length);
  }

}
