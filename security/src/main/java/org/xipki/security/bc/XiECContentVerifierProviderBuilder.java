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

package org.xipki.security.bc;

import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.xipki.security.DSAPlainDigestSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;

/**
 * Extends {@link BcECContentVerifierProviderBuilder} to support the signature algorithms
 * Plain-ECDSA and SM3.
 *
 * @author Lijun Liao
 * @since 2.1.0
 */

// CHECKSTYLE:SKIP
public class XiECContentVerifierProviderBuilder extends BcECContentVerifierProviderBuilder {

  private static final DigestAlgorithmIdentifierFinder digestAlgorithmFinder
      = XiDigestAlgorithmIdentifierFinder.INSTANCE;

  public XiECContentVerifierProviderBuilder() {
    super(digestAlgorithmFinder);
  }

  @Override
  protected Signer createSigner(AlgorithmIdentifier sigAlgId)
      throws OperatorCreationException {
    SignAlgo signAlgo;
    try {
      signAlgo = SignAlgo.getInstance(sigAlgId);
    } catch (NoSuchAlgorithmException ex) {
      throw new OperatorCreationException(ex.getMessage(), ex);
    }

    HashAlgo hashAlgo = signAlgo.getHashAlgo();

    if (SignAlgo.SM2_SM3 == signAlgo) {
      return new SM2Signer();
    } else if (signAlgo.isPlainECDSASigAlgo()) {
      return new DSAPlainDigestSigner(new ECDSASigner(), hashAlgo.createDigest());
    } else {
      return new DSADigestSigner(new ECDSASigner(), hashAlgo.createDigest());
    }
  } // method createSigner

}
