// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

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
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiSecurityException;
import org.xipki.security.bc.XiECContentVerifierProviderBuilder;
import org.xipki.security.bc.XiEdDSAContentVerifierProvider;
import org.xipki.security.bc.XiRSAContentVerifierProviderBuilder;
import org.xipki.security.bc.XiXDHContentVerifierProvider;
import org.xipki.util.Args;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;

/**
 * utility class for converting java.security RSA objects into their
 * org.bouncycastle.crypto counterparts.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class SignerUtil {

  private static final DigestAlgorithmIdentifierFinder DIGESTALG_IDENTIFIER_FINDER
      = new DefaultDigestAlgorithmIdentifierFinder();

  private static final Map<String, BcContentVerifierProviderBuilder> VERIFIER_PROVIDER_BUILDER = new HashMap<>();

  private SignerUtil() {
  }

  public static RSAKeyParameters generateRSAPrivateKeyParameter(RSAPrivateKey key) {
    Args.notNull(key, "key");
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
    if (!Args.notNull(sigAlgo, "sigAlgo").isRSAPSSSigAlgo()) {
      throw new XiSecurityException(sigAlgo + " is not an RSAPSS algorithm");
    }

    HashAlgo hashAlgo = sigAlgo.getHashAlgo();
    return new PSSSigner(new RSABlindedEngine(), hashAlgo.createDigest(), hashAlgo.createDigest(), hashAlgo.getLength(),
        org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT);
  } // method createPSSRSASigner

  public static ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey, DHSigStaticKeyCertPair ownerKeyAndCert) throws InvalidKeyException {
    String keyAlg = Args.notNull(publicKey, "publicKey").getAlgorithm().toUpperCase();
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
