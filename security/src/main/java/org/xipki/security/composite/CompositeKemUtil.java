// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.util.BigIntegers;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.encap.SecretWithEncap;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.PKCS1Util;
import org.xipki.util.io.IoUtil;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * @author Lijun Liao (xipki)
 */
public class CompositeKemUtil {

  public static SecretWithEncap encap(CompositeKemSuite algoSuite,
                                      byte[] pk, SecureRandom rnd)
      throws XiSecurityException {
    MlkemVariant mlkemVariant = algoSuite.mlkemVariant();
    KemTradVariant tradVariant = algoSuite.tradVariant();
    byte[] mlkemPk = Arrays.copyOfRange(pk, 0, mlkemVariant.pkSize());
    byte[] tradPk = Arrays.copyOfRange(pk, mlkemVariant.pkSize(),
        pk.length);

    SecretWithEncap mlkemRes = mlKemEcapsulate(mlkemVariant, mlkemPk, rnd);
    SecretWithEncap tradRes  = tradEcapsulate(tradVariant, tradPk, rnd);
    byte[] ct = IoUtil.concatenate(mlkemRes.getEncap(), tradRes.getEncap());
    byte[] k = sha3256Kdf(mlkemRes.getSecret(),
        tradRes.getSecret(), tradRes.getEncap(), tradPk,
        algoSuite.label());
    return new SecretWithEncap(k, ct);
  }

  private static SecretWithEncap mlKemEcapsulate(
      MlkemVariant variant, byte[] pk, SecureRandom rnd) {
    MLKEMGenerator enc = new MLKEMGenerator(rnd);
    SecretWithEncapsulation res = enc.generateEncapsulated(
        new MLKEMPublicKeyParameters(variant.params(), pk));
    return new SecretWithEncap(res.getSecret(), res.getEncapsulation());
  }

  private static SecretWithEncap tradEcapsulate(
      KemTradVariant variant, byte[] pk, SecureRandom rnd)
      throws XiSecurityException {
    switch (variant) {
      case X25519: {
        byte[] tmpSk = new byte[32];
        X25519.generatePrivateKey(rnd, tmpSk);
        byte[] tmpPk = new byte[32]; // ct
        X25519.generatePublicKey(tmpSk, 0, tmpPk, 0);
        byte[] k = new byte[32]; // k
        X25519.calculateAgreement(tmpSk, 0, pk, 0,
            k, 0);
        return new SecretWithEncap(k, tmpPk);
      }
      case X448: {
        byte[] tmpSk = new byte[56];
        X448.generatePrivateKey(rnd, tmpSk);
        byte[] tmpPk = new byte[56]; // ct
        X448.generatePublicKey(tmpSk, 0, tmpPk, 0);
        byte[] k = new byte[56]; // k
        X448.calculateAgreement(tmpSk, 0, pk, 0,
            k, 0);
        return new SecretWithEncap(k, tmpPk);
      }
      case ECDH_P256:
      case ECDH_P384:
      case ECDH_P521:
      case ECDH_BP256:
      case ECDH_BP384: {
        WeierstraussCurveEnum curveEnum;
        switch (variant) {
          case ECDH_P256:
            curveEnum = WeierstraussCurveEnum.P256;
            break;
          case ECDH_P384:
            curveEnum = WeierstraussCurveEnum.P384;
            break;
          case ECDH_P521:
            curveEnum = WeierstraussCurveEnum.P521;
            break;
          case ECDH_BP256:
            curveEnum = WeierstraussCurveEnum.BP256;
            break;
          default:
            curveEnum = WeierstraussCurveEnum.BP384;
            break;
        }

        BigInteger order = curveEnum.order();
        byte[] tmpSk = new byte[curveEnum.fieldByteSize()];
        rnd.nextBytes(tmpSk);
        BigInteger tmpSkBn = new BigInteger(1, tmpSk).mod(order);

        byte[] tmpPk = curveEnum.multiplyBase(tmpSkBn).normalize()
                        .getEncoded(false);

        BigInteger agreedSs = curveEnum.decodePoint(pk)
            .multiply(tmpSkBn).normalize().getAffineXCoord().toBigInteger();
        return new SecretWithEncap(
            BigIntegers.asUnsignedByteArray(
                curveEnum.fieldByteSize(), agreedSs),
            tmpPk);
      }
      case RSA2048_OAEP:
      case RSA3072_OAEP:
      case RSA4096_OAEP: {
        byte[] k = new byte[32];
        rnd.nextBytes(k);
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
            variant.keySpec().getAlgorithmIdentifier(), pk);

        try {
          RSAPublicKey jceSk = (RSAPublicKey)
              BouncyCastleProvider.getPublicKey(spki);
          BigInteger modulus = jceSk.getModulus();
          Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
          cipher.init(Cipher.ENCRYPT_MODE, jceSk);
          byte[] em = PKCS1Util.RSAES_OAEP_ENCODE(k, modulus.bitLength(),
                        HashAlgo.SHA256, rnd);
          byte[] ct = cipher.doFinal(em);
          return new SecretWithEncap(k, ct);
        } catch (XiSecurityException e) {
          throw e;
        } catch (Exception e) {
          throw new XiSecurityException(e);
        }
      }
      default:
        throw new IllegalStateException("shall not reach here");
    }
  }

  public static byte[] sha3256Kdf(byte[] mlkemSS, byte[] tradSS, byte[] tradCT,
                         byte[] tradPK, byte[] label) {
    return HashAlgo.SHA3_256.hash(mlkemSS, tradSS, tradCT, tradPK, label);
  }

  public static byte[] decap(CompositeKemSuite algoSuite,
                             byte[] sk, byte[] pk, byte[] ct)
      throws XiSecurityException {
    MlkemVariant mlkemVariant = algoSuite.mlkemVariant();

    byte[] mlkemSk = Arrays.copyOfRange(sk, 0, mlkemVariant.skSize());
    int off = mlkemVariant.skSize();
    byte[] tradSk  = Arrays.copyOfRange(sk, off, sk.length);

    byte[] mlkemCT  = Arrays.copyOfRange(ct, 0, mlkemVariant.ctSize());
    byte[] tradCT  = Arrays.copyOfRange(ct, mlkemVariant.ctSize(), ct.length);
    byte[] tradPk = Arrays.copyOfRange(pk, mlkemVariant.pkSize(), pk.length);

    byte[] mlkemSS = decapMlkem(mlkemVariant, mlkemSk, mlkemCT);
    byte[] tradSS = decapTrad(algoSuite.tradVariant(), tradSk, tradCT);
    return sha3256Kdf(mlkemSS, tradSS, tradCT, tradPk, algoSuite.label());
  }

  private static byte[] decapMlkem(MlkemVariant variant, byte[] sk, byte[] ct) {
    MLKEMPrivateKeyParameters dkObj = new MLKEMPrivateKeyParameters(
        variant.params(), sk);
    MLKEMExtractor extractor = new MLKEMExtractor(dkObj);
    return extractor.extractSecret(ct);
  }

  private static byte[] decapTrad(
      KemTradVariant variant, byte[] sk, byte[] ct)
      throws XiSecurityException {
    switch (variant) {
      case X25519:
      case X448: {
        boolean isX448 = variant == KemTradVariant.X448;
        int size = isX448 ? 56 : 32;
        if (sk.length != size) {
          throw new XiSecurityException("invalid sk.length " + sk.length);
        }
        if (ct.length != size) {
          throw new XiSecurityException("invalid ct.length " + sk.length);
        }
        byte[] r = new byte[size];
        if (isX448) {
          X448.calculateAgreement(sk, 0, ct, 0, r, 0);
        } else {
          X25519.calculateAgreement(sk, 0, ct, 0, r, 0);
        }
        return r;
      }
      case RSA2048_OAEP:
      case RSA3072_OAEP:
      case RSA4096_OAEP: {
        try {
          PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
              new AlgorithmIdentifier(OIDs.Algo.id_rsaEncryption,
                  DERNull.INSTANCE),
              sk);
          RSAPrivateKey jceSk = (RSAPrivateKey)
              BouncyCastleProvider.getPrivateKey(privateKeyInfo);
          BigInteger modulus = jceSk.getModulus();
          Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
          cipher.init(Cipher.DECRYPT_MODE, jceSk);
          byte[] em = cipher.doFinal(ct);
          return PKCS1Util.RSAES_OAEP_DECODE(em, modulus.bitLength(),
                  HashAlgo.SHA256);
        } catch (XiSecurityException e) {
          throw e;
        } catch (Exception e) {
          throw new XiSecurityException(e);
        }
      }
      case ECDH_P256:
      case ECDH_P384:
      case ECDH_P521:
      case ECDH_BP256:
      case ECDH_BP384: {
        WeierstraussCurveEnum curve;
        switch (variant) {
          case ECDH_P256:
            curve = WeierstraussCurveEnum.P256;
            break;
          case ECDH_P384:
            curve = WeierstraussCurveEnum.P384;
            break;
          case ECDH_P521:
            curve = WeierstraussCurveEnum.P521;
            break;
          case ECDH_BP256:
            curve = WeierstraussCurveEnum.BP256;
            break;
          default:
            curve = WeierstraussCurveEnum.BP384;
            break;
        }

        ECPrivateKey asn1Sk = ECPrivateKey.getInstance(sk);
        byte[] encoded = curve.decodePoint(ct).multiply(
            asn1Sk.getKey()).normalize().getEncoded(false);
        return Arrays.copyOfRange(encoded, 1, 1 + encoded.length / 2);
      }
      default:
        throw new IllegalStateException("unknown variant " + variant);
    }
  }

}
