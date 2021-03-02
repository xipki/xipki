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

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
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
import org.xipki.security.util.AlgorithmUtil;

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
    AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
    HashAlgo hashAlgo = HashAlgo.getInstance(digAlg.getAlgorithm());

    boolean plainDsa = AlgorithmUtil.isPlainECDSASigAlg(sigAlgId);

    if (plainDsa) {
      return new DSAPlainDigestSigner(new ECDSASigner(), hashAlgo.createDigest());
    }

    boolean sm2 = AlgorithmUtil.isSM2SigAlg(sigAlgId);
    if (sm2) {
      if (GMObjectIdentifiers.sm3.equals(digAlg.getAlgorithm())) {
        return new SM2Signer();
      } else {
        throw new OperatorCreationException("cannot create SM2 signer for hash algorithm "
            + digAlg.getAlgorithm().getId());
      }
    }

    return new DSADigestSigner(new ECDSASigner(), hashAlgo.createDigest());
  } // method createSigner

}
