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

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.operator.bc.BcDigestProvider;
import org.xipki.security.HashAlgo;

/**
 * Extends the BcDefaultDigestProvider to support SHAKE* digests.
 *
 * @author Lijun Liao
 *
 */
public class XiDigestProvider implements BcDigestProvider {

  public static final XiDigestProvider INSTANCE = new XiDigestProvider();

  private XiDigestProvider() {
  }

  @Override
  public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
      throws OperatorCreationException {
    HashAlgo ha = HashAlgo.getInstance(digestAlgorithmIdentifier.getAlgorithm());
    if (ha != null) {
      return ha.createDigest();
    } else {
      return BcDefaultDigestProvider.INSTANCE.get(digestAlgorithmIdentifier);
    }
  }

}
