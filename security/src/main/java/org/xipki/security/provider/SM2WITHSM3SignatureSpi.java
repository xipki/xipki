// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.provider;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.math.ec.ECPoint;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.WeierstraussCurveEnum;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * SM2 WITHSM3 Signature Spi.
 *
 * @author Lijun Liao (xipki)
 */
public class SM2WITHSM3SignatureSpi extends SignatureSpi {

  private MessageDigest digest;

  private byte[] za;

  private BigInteger sk;

  private ECPoint pk;

  private ECPrivateKey jceSk;

  private ECPublicKey jcePk;

  private Boolean forSign;

  private SecureRandom random;

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    if (!(publicKey instanceof ECPublicKey)) {
      throw new InvalidKeyException("invalid publicKey");
    }

    this.forSign = false;
    jceSk = null;
    sk = null;

    if (jcePk != publicKey) {
      SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      assertSm2Curve(pkInfo.getAlgorithm());
      this.sk = null;
      this.jceSk = null;
      this.jcePk = (ECPublicKey) publicKey;
      try {
        this.pk = WeierstraussCurveEnum.SM2.decodePoint(Asn1Util.getPublicKeyData(pkInfo));
        this.za = GMUtil.getSM2Z(null, this.pk.getXCoord().toBigInteger(),
                      this.pk.getYCoord().toBigInteger());
      } catch (XiSecurityException e) {
        throw new InvalidKeyException(e);
      }
    }

    initDigest();
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    engineInitSign(privateKey, null);
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
      throws InvalidKeyException {
    if (!(privateKey instanceof ECPrivateKey)) {
      throw new InvalidKeyException("invalid privateKey");
    }

    this.forSign = true;
    this.jcePk = null;

    if (jceSk != privateKey) {
      PrivateKeyInfo skInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
      assertSm2Curve(skInfo.getPrivateKeyAlgorithm());

      org.bouncycastle.asn1.sec.ECPrivateKey asn1Sk =
          org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(skInfo.getPrivateKey().getOctets());
      this.sk = asn1Sk.getKey();
      this.jceSk = (ECPrivateKey) privateKey;

      byte[] pkData = Asn1Util.getECPublicKeyData(asn1Sk, skInfo);
      if (pkData != null) {
        try {
          this.pk = WeierstraussCurveEnum.SM2.decodePoint(pkData);
        } catch (XiSecurityException e) {
        }
      }

      if (this.pk == null) {
        this.pk = WeierstraussCurveEnum.SM2.multiplyBase(sk);
      }

      this.za = GMUtil.getSM2Z(null, this.pk.getXCoord().toBigInteger(),
          this.pk.getYCoord().toBigInteger());
    }

    if (random != null) {
      this.random = random;
    } else if (this.random == null) {
      this.random = new SecureRandom();
    }

    initDigest();
  }

  @Override
  protected void engineUpdate(byte b) throws SignatureException {
    digest.update(b);
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
    digest.update(b, off, len);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (forSign != null && forSign) {
      byte[] ehash = digest.digest();
      return GMUtil.signRawSm2(sk, ehash, random);
    } else {
      throw new SignatureException("Signature has not been initialized for sign");
    }
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (forSign != null && !forSign) {
      byte[] ehash = digest.digest();
      return GMUtil.verifyRawSm2(pk, ehash, sigBytes);
    } else {
      throw new SignatureException("Signature has not been initialized for verify");
    }
  }

  @Override
  protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    throw new InvalidParameterException("engineSetParameter not supported");
  }

  @Override
  protected Object engineGetParameter(String param) throws InvalidParameterException {
    throw new InvalidParameterException("engineGetParameter not supported");
  }

  private static void assertSm2Curve(AlgorithmIdentifier algId) throws InvalidKeyException {
    if (algId.getAlgorithm().equals(OIDs.Algo.id_ecPublicKey) &&
        OIDs.Curve.sm2p256v1.equals(algId.getParameters())) {
      return;
    }
    throw new InvalidKeyException("given key is not an EC key with SM2 curve");
  }

  private void initDigest() {
    if (digest == null) {
      digest = HashAlgo.SM3.createDigest();
    } else {
      digest.reset();
    }

    digest.update(za);
  }

}
