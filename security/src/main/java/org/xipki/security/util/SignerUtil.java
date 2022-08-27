/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiSecurityException;
import org.xipki.security.asn1.Asn1StreamParser;
import org.xipki.security.bc.XiECContentVerifierProviderBuilder;
import org.xipki.security.bc.XiEdDSAContentVerifierProvider;
import org.xipki.security.bc.XiRSAContentVerifierProviderBuilder;
import org.xipki.security.bc.XiXDHContentVerifierProvider;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;

import static org.xipki.util.Args.notNull;

/**
 * utility class for converting java.security RSA objects into their
 * org.bouncycastle.crypto counterparts.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerUtil {

  private static final DigestAlgorithmIdentifierFinder DIGESTALG_IDENTIFIER_FINDER
      = new DefaultDigestAlgorithmIdentifierFinder();

  private static final Map<String, BcContentVerifierProviderBuilder> VERIFIER_PROVIDER_BUILDER = new HashMap<>();

  private SignerUtil() {
  }

  public static RSAKeyParameters generateRSAPrivateKeyParameter(RSAPrivateKey key) {
    notNull(key, "key");
    if (key instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;

      return new RSAPrivateCrtKeyParameters(rsaKey.getModulus(), rsaKey.getPublicExponent(),
          rsaKey.getPrivateExponent(), rsaKey.getPrimeP(), rsaKey.getPrimeQ(),
          rsaKey.getPrimeExponentP(), rsaKey.getPrimeExponentQ(), rsaKey.getCrtCoefficient());
    } else {
      return new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());
    }
  }

  public static Signer createPSSRSASigner(SignAlgo sigAlgo) throws XiSecurityException {
    return createPSSRSASigner(sigAlgo, null);
  }

  public static Signer createPSSRSASigner(SignAlgo sigAlgo, AsymmetricBlockCipher cipher)
      throws XiSecurityException {
    notNull(sigAlgo, "sigAlgo");
    if (!sigAlgo.isRSAPSSSigAlgo()) {
      throw new XiSecurityException(sigAlgo + " is not an RSAPSS algorithm");
    }

    HashAlgo hashAlgo = sigAlgo.getHashAlgo();

    AsymmetricBlockCipher tmpCipher = (cipher == null) ? new RSABlindedEngine() : cipher;

    Digest dig = hashAlgo.createDigest();
    Digest mgfDig = hashAlgo.createDigest();

    return new PSSSigner(tmpCipher, dig, mgfDig, hashAlgo.getLength(),
        org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT);
  } // method createPSSRSASigner

  public static byte[] dsaSigPlainToX962(byte[] signature) throws XiSecurityException {
    notNull(signature, "signature");
    if (signature.length % 2 != 0) {
      throw new XiSecurityException("signature.lenth must be even, but is odd");
    }
    byte[] ba = new byte[signature.length / 2];
    ASN1EncodableVector sigder = new ASN1EncodableVector();

    System.arraycopy(signature, 0, ba, 0, ba.length);
    sigder.add(new ASN1Integer(new BigInteger(1, ba)));

    System.arraycopy(signature, ba.length, ba, 0, ba.length);
    sigder.add(new ASN1Integer(new BigInteger(1, ba)));

    DERSequence seq = new DERSequence(sigder);
    try {
      return seq.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("IOException, message: " + ex.getMessage(), ex);
    }
  } // method dsaSigPlainToX962

  public static byte[] dsaSigX962ToPlain(byte[] x962Signature, int keyBitLen)
      throws XiSecurityException {
    notNull(x962Signature, "x962Signature");
    try {
      BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(x962Signature));
      int tag = Asn1StreamParser.markAndReadTag(is);
      Asn1StreamParser.assertTag(Asn1StreamParser.TAG_CONSTRUCTED_SEQUENCE, tag, "X962Signature");
      Asn1StreamParser.MyInt lenBytesLen = new Asn1StreamParser.MyInt();
      int len = Asn1StreamParser.readLength(lenBytesLen, is);
      if (1 + lenBytesLen.get() + len != x962Signature.length) {
        throw new XiSecurityException("invalid length");
      }

      // r
      byte[] r = Asn1StreamParser.readValue(0x02, is, "r");

      // s
      byte[] s = Asn1StreamParser.readValue(0x02, is, "s");
      return dsaSigToPlain(new BigInteger(1, r), new BigInteger(1, s), keyBitLen);
    } catch (IOException ex) {
      throw new XiSecurityException("error parsing X509Signature", ex);
    }
  } // method dsaSigX962ToPlain

  public static byte[] dsaSigToPlain(BigInteger sigR, BigInteger sigS, int keyBitLen)
      throws XiSecurityException {
    notNull(sigR, "sigR");
    notNull(sigS, "sigS");

    final int blockSize = (keyBitLen + 7) / 8;
    int bitLenOfR = sigR.bitLength();
    int bitLenOfS = sigS.bitLength();
    int bitLen = Math.max(bitLenOfR, bitLenOfS);
    if ((bitLen + 7) / 8 > blockSize) {
      throw new XiSecurityException("signature is too large");
    }

    byte[] plainSignature = new byte[2 * blockSize];
    bigIntToBytes(sigR, plainSignature, 0, blockSize);
    bigIntToBytes(sigS, plainSignature, blockSize, blockSize);
    return plainSignature;
  } // method dsaSigToPlain

  private static void bigIntToBytes(BigInteger num, byte[] dest, int destPos, int length) {
    byte[] bytes = num.toByteArray();
    if (bytes.length == length) {
      System.arraycopy(bytes, 0, dest, destPos, length);
    } else if (bytes.length < length) {
      System.arraycopy(bytes, 0, dest, destPos + length - bytes.length, bytes.length);
    } else {
      System.arraycopy(bytes, bytes.length - length, dest, destPos, length);
    }
  } // method bigIntToBytes

  public static ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey, DHSigStaticKeyCertPair ownerKeyAndCert)
      throws InvalidKeyException {
    notNull(publicKey, "publicKey");

    String keyAlg = publicKey.getAlgorithm().toUpperCase();
    if ("ED25519".equals(keyAlg) || "ED448".equals(keyAlg)) {
      return new XiEdDSAContentVerifierProvider(publicKey);
    } else if ("X25519".equals(keyAlg) || "X448".equals(keyAlg)) {
      if (ownerKeyAndCert == null) {
        throw new InvalidKeyException("ownerKeyAndCert is required but absent");
      }
      return new XiXDHContentVerifierProvider(publicKey, ownerKeyAndCert);
    }

    BcContentVerifierProviderBuilder builder = VERIFIER_PROVIDER_BUILDER.get(keyAlg);

    if (builder == null) {
      switch (keyAlg) {
        case "RSA":
          builder = new XiRSAContentVerifierProviderBuilder();
          break;
        case "DSA":
          builder = new BcDSAContentVerifierProviderBuilder(DIGESTALG_IDENTIFIER_FINDER);
          break;
        case "EC":
        case "ECDSA":
          builder = new XiECContentVerifierProviderBuilder();
          break;
        default:
          throw new InvalidKeyException("unknown key algorithm of the public key " + keyAlg);
      }
      VERIFIER_PROVIDER_BUILDER.put(keyAlg, builder);
    }

    AsymmetricKeyParameter keyParam = KeyUtil.generatePublicKeyParameter(publicKey);
    try {
      return builder.build(keyParam);
    } catch (OperatorCreationException ex) {
      throw new InvalidKeyException("could not build ContentVerifierProvider: " + ex.getMessage(), ex);
    }
  } // method getContentVerifierProvider

}
