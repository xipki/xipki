// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bc;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.SignerUtil;

import java.security.NoSuchAlgorithmException;

/**
 * Extends {@link BcECContentVerifierProviderBuilder} to support the signature algorithms
 * RSAPSS.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class XiRSAContentVerifierProviderBuilder extends BcRSAContentVerifierProviderBuilder {
  private static final DigestAlgorithmIdentifierFinder digestAlgorithmFinder
      = new DefaultDigestAlgorithmIdentifierFinder();

  public XiRSAContentVerifierProviderBuilder() {
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

    if (signAlgo.isRSAPSSSigAlgo()) {
      try {
        return SignerUtil.createPSSRSASigner(signAlgo);
      } catch (XiSecurityException ex) {
        throw new OperatorCreationException(ex.getMessage(), ex);
      }
    } else {
      AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
      return new RSADigestSigner(digestProvider.get(digAlg));
    }
  }

}
