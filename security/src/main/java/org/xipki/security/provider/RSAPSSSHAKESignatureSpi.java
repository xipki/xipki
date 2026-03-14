// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.provider;

import org.bouncycastle.util.BigIntegers;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.PKCS1Util;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class RSAPSSSHAKESignatureSpi extends SignatureSpi {

  private final SignAlgo signAlgo;

  private MessageDigest digest;

  private Boolean forSign;

  private SecureRandom random;

  private RSAPrivateKey rsaPrivateKey;
  private RSAPublicKey  rsaPublicKey;

  private RSAPSSSHAKESignatureSpi(SignAlgo signAlgo) {
    this.signAlgo = Args.notNull(signAlgo, "signAlgo");
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    if (!(publicKey instanceof RSAPublicKey)) {
      throw new InvalidKeyException("invalid publicKey");
    }

    this.rsaPublicKey = (RSAPublicKey) publicKey;
    this.forSign = false;
    reset();
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    engineInitSign(privateKey, null);
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
      throws InvalidKeyException {
    if (!(privateKey instanceof RSAPrivateKey)) {
      throw new InvalidKeyException("invalid privateKey");
    }
    this.rsaPrivateKey = (RSAPrivateKey) privateKey;

    this.forSign = true;
    if (random != null) {
      this.random = random;
    } else if (this.random == null) {
      this.random = KeyUtil.random();
    }

    reset();
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
    if (forSign == null || !forSign) {
      throw new SignatureException("Signature has not been initialized for sign");
    }

    BigInteger modulus = rsaPrivateKey.getModulus();

    byte[] mhash = digest.digest();
    HashAlgo ha = signAlgo.hashAlgo();
    byte[] rawInput;
    try {
      rawInput = PKCS1Util.EMSA_PSS_ENCODE(ha, mhash, ha, ha.length(), modulus.bitLength(), random);
    } catch (XiSecurityException e) {
      throw new SignatureException(e);
    }

    return signRaw(rawInput);
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (forSign == null || forSign) {
      throw new SignatureException("Signature has not been initialized for verify");
    }

    BigInteger bnSig = new BigInteger(1, sigBytes);
    BigInteger modulus = rsaPublicKey.getModulus();
    BigInteger bnEM = bnSig.modPow(rsaPublicKey.getPublicExponent(), modulus);

    byte[] EM = BigIntegers.asUnsignedByteArray((modulus.bitLength() + 7) / 8, bnEM);

    byte[] mhash = digest.digest();
    HashAlgo ha = signAlgo.hashAlgo();
    try {
      return PKCS1Util.EMSA_PSS_DECODE(ha, mhash, EM, ha.length(), modulus.bitLength());
    } catch (XiSecurityException e) {
      throw new SignatureException(e);
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

  private void reset() {
    if (digest == null) {
      digest = signAlgo.hashAlgo().createDigest();
    } else {
      digest.reset();
    }
  }

  private byte[] signRaw(byte[] em) throws SignatureException {
    int modulusBitSize = rsaPrivateKey.getModulus().bitLength();
    if (em.length * 8 != modulusBitSize) {
      throw new SignatureException("em.length != " + (modulusBitSize / 8) + ": " + em.length);
    }

    BigInteger c;
    if (rsaPrivateKey instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey sk = (RSAPrivateCrtKey) rsaPrivateKey;
      BigInteger p    = sk.getPrimeP();
      BigInteger q    = sk.getPrimeQ();
      BigInteger dP   = sk.getPrimeExponentP();
      BigInteger dQ   = sk.getPrimeExponentQ();
      BigInteger qInv = sk.getCrtCoefficient();

      BigInteger m  = new BigInteger(1, em);
      BigInteger m1 = m.modPow(dP, p);
      BigInteger m2 = m.modPow(dQ, q);

      BigInteger m1_m2 = m1.subtract(m2).mod(p);
      if (m1_m2.signum() < 0) {
        m1_m2 = m1_m2.add(p);
      }
      BigInteger h = qInv.multiply(m1_m2).mod(p);
      c = m2.add(h.multiply(q));
    } else {
      BigInteger d = rsaPrivateKey.getPrivateExponent();
      BigInteger m = new BigInteger(1, em);
      c = m.modPow(d, rsaPrivateKey.getModulus());
    }

    return BigIntegers.asUnsignedByteArray(em.length, c);
  }

  public static class RSAPSSSHAKE128 extends RSAPSSSHAKESignatureSpi {

    public RSAPSSSHAKE128() {
      super(SignAlgo.RSAPSS_SHAKE128);
    }

  }

  public static class RSAPSSSHAKE256 extends RSAPSSSHAKESignatureSpi {

    public RSAPSSSHAKE256() {
      super(SignAlgo.RSAPSS_SHAKE256);
    }

  }

}
