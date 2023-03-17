// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11.emulator;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.GMUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * The RAW SM2 Digital Signature algorithm. The message is the hash value over the real message.
 *
 * @author Lijun Liao (xipki)
 *
 */
class EmulatorSM2Signer {
  private final DSAKCalculator kCalculator = new RandomDSAKCalculator();

  private final Digest digest;

  private final ECDomainParameters ecParams;

  private final ECKeyParameters ecKey;

  private final ECPoint pubPoint;

  public EmulatorSM2Signer(CipherParameters param) {
    if (param instanceof ParametersWithRandom) {
      ParametersWithRandom rdmParam = (ParametersWithRandom) param;

      ecKey = (ECKeyParameters)rdmParam.getParameters();
      ecParams = ecKey.getParameters();
      kCalculator.init(ecParams.getN(), rdmParam.getRandom());
    } else {
      ecKey = (ECKeyParameters) param;
      ecParams = ecKey.getParameters();
      kCalculator.init(ecParams.getN(), new SecureRandom());
    }

    if (!GMUtil.isSm2primev2Curve(ecKey.getParameters().getCurve())) {
      throw new IllegalArgumentException("Given EC key is not of the curve sm2primev2");
    }

    this.pubPoint = new FixedPointCombMultiplier().multiply(ecParams.getG(),
        ((ECPrivateKeyParameters)ecKey).getD()).normalize();

    this.digest = HashAlgo.SM3.createDigest();
  } // constructor

  public byte[] generateSignatureForMessage(byte[] userId, byte[] message) throws CryptoException {
    byte[] z = GMUtil.getSM2Z(userId, GMObjectIdentifiers.sm2p256v1, pubPoint.getAffineXCoord().toBigInteger(),
                  pubPoint.getAffineYCoord().toBigInteger());
    digest.reset();
    digest.update(z, 0, z.length);
    digest.update(message, 0, message.length);
    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);
    return generateSignatureForHash(hash);
  } // method generateSignatureForMessage

  public byte[] generateSignatureForHash(byte[] eHash) throws CryptoException {
    BigInteger n = ecParams.getN();
    BigInteger e = new BigInteger(1, eHash);
    BigInteger d = ((ECPrivateKeyParameters)ecKey).getD();

    BigInteger r;
    BigInteger s;

    ECMultiplier basePointMultiplier = new FixedPointCombMultiplier();

    // 5.2.1 Draft RFC:  SM2 Public Key Algorithms
    do { // generate s
      BigInteger k;
      do { // generate r
        // A3
        k = kCalculator.nextK();

        // A4
        ECPoint p = basePointMultiplier.multiply(ecParams.getG(), k).normalize();

        // A5
        r = e.add(p.getAffineXCoord().toBigInteger()).mod(n);
      } while (r.equals(ECConstants.ZERO) || r.add(k).equals(n));

      // A6
      BigInteger dPlus1ModN = d.add(ECConstants.ONE).modInverse(n);

      s = k.subtract(r.multiply(d)).mod(n);
      s = dPlus1ModN.multiply(s).mod(n);
    } while (s.equals(ECConstants.ZERO));

    // A7
    try {
      return new DERSequence(new ASN1Integer[]{new ASN1Integer(r), new ASN1Integer(s)}).getEncoded(ASN1Encoding.DER);
    } catch (IOException ex) {
      throw new CryptoException("unable to encode signature: " + ex.getMessage(), ex);
    }
  } // method generateSignatureForHash

}
