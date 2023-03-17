// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bc;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.xipki.security.DSAPlainDigestSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;

import java.security.NoSuchAlgorithmException;

/**
 * Extends {@link BcECContentVerifierProviderBuilder} to support the signature algorithms
 * Plain-ECDSA and SM3.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class XiECContentVerifierProviderBuilder extends BcECContentVerifierProviderBuilder {

  private static final DigestAlgorithmIdentifierFinder digestAlgorithmFinder
      = new DefaultDigestAlgorithmIdentifierFinder();

  public XiECContentVerifierProviderBuilder() {
    super(digestAlgorithmFinder);
  }

  @Override
  protected Signer createSigner(AlgorithmIdentifier sigAlgId) throws OperatorCreationException {
    SignAlgo signAlgo;
    try {
      signAlgo = SignAlgo.getInstance(sigAlgId);
    } catch (NoSuchAlgorithmException ex) {
      throw new OperatorCreationException(ex.getMessage(), ex);
    }

    if (signAlgo == null) {
      throw new OperatorCreationException("could not detect SignAlgo from sigAlgId");
    }

    HashAlgo hashAlgo = signAlgo.getHashAlgo();

    return (SignAlgo.SM2_SM3 == signAlgo) ? new SM2Signer()
        : signAlgo.isPlainECDSASigAlgo()  ? new DSAPlainDigestSigner(new ECDSASigner(), hashAlgo.createDigest())
        : new DSADigestSigner(new ECDSASigner(), hashAlgo.createDigest());
  } // method createSigner

}
