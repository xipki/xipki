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

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers.Shake;

/**
 * Extends the DefaultDigestAlgorithmIdentifierFinder to support SHAKE* digests.
 *
 * @author Lijun Liao
 *
 */

public class XiDigestAlgorithmIdentifierFinder
    implements DigestAlgorithmIdentifierFinder {

  public static final XiDigestAlgorithmIdentifierFinder INSTANCE
      = new XiDigestAlgorithmIdentifierFinder();

  private static final Map<ASN1ObjectIdentifier, HashAlgo> digestOids = new HashMap<>();
  private static final Map<String, HashAlgo> digestNameToOids = new HashMap<>();
  private static final DigestAlgorithmIdentifierFinder dfltFinder
      = new DefaultDigestAlgorithmIdentifierFinder();

  static {
    digestOids.put(Shake.id_ecdsa_with_shake128, HashAlgo.SHAKE128);
    digestOids.put(Shake.id_ecdsa_with_shake256, HashAlgo.SHAKE256);
    digestOids.put(Shake.id_RSASSA_PSS_SHAKE128, HashAlgo.SHAKE128);
    digestOids.put(Shake.id_RSASSA_PSS_SHAKE256, HashAlgo.SHAKE256);

    digestNameToOids.put("SHAKE128", HashAlgo.SHAKE128);
    digestNameToOids.put("SHAKE128-256", HashAlgo.SHAKE128);
    digestNameToOids.put("SHAKE256", HashAlgo.SHAKE256);
    digestNameToOids.put("SHAKE256-512", HashAlgo.SHAKE256);
  }

  @Override
  public AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId) {
    HashAlgo algo = digestOids.get(sigAlgId.getAlgorithm());
    if (algo != null) {
      return algo.getAlgorithmIdentifier();
    } else {
      return dfltFinder.find(sigAlgId);
    }
  }

  @Override
  public AlgorithmIdentifier find(String digAlgName) {
    HashAlgo algo = digestNameToOids.get(digAlgName.toUpperCase());
    if (algo != null) {
      return algo.getAlgorithmIdentifier();
    } else {
      return dfltFinder.find(digAlgName);
    }
  }

}
