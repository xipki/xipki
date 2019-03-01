/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.SignerUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

// CHECKSTYLE:SKIP
public class XiRSAContentVerifierProviderBuilder extends BcRSAContentVerifierProviderBuilder {
  private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

  public XiRSAContentVerifierProviderBuilder(
      DigestAlgorithmIdentifierFinder digestAlgorithmFinder) {
    super(digestAlgorithmFinder);
    this.digestAlgorithmFinder = digestAlgorithmFinder;
  }

  @Override
  protected Signer createSigner(AlgorithmIdentifier sigAlgId) throws OperatorCreationException {
    if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm())) {
      try {
        return SignerUtil.createPSSRSASigner(sigAlgId);
      } catch (XiSecurityException ex) {
        throw new OperatorCreationException(ex.getMessage(), ex);
      }
    } else {
      AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
      return new RSADigestSigner(digestProvider.get(digAlg));
    }
  }

}
