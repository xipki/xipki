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

package org.xipki.security;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.Args;

/**
 * An implementation of {@link AlgorithmValidator} where the permitted algorithms
 * are contained in a static collection.
 *
 * @author Lijun Liao
 * @since 2.1.0
 */

public class CollectionAlgorithmValidator implements AlgorithmValidator {

  private final Set<String> algoNames;

  /**
   * constructor.
   * @param algoNames algorithm names that can be accepted. <code>null</code> or empty to accept
   *            all algorithms
   * @throws NoSuchAlgorithmException if any algoName is unknown.
   */
  public CollectionAlgorithmValidator(Collection<String> algoNames)
      throws NoSuchAlgorithmException {
    Set<String> canonicalizedNames = new HashSet<>();
    if (algoNames != null) {
      for (String m : algoNames) {
        //
        canonicalizedNames.add(AlgorithmUtil.canonicalizeSignatureAlgo(m));
      }
    }
    this.algoNames = Collections.unmodifiableSet(canonicalizedNames);
  }

  public Set<String> getAlgoNames() {
    return algoNames;
  }

  @Override
  public boolean isAlgorithmPermitted(AlgorithmIdentifier algId) {
    Args.notNull(algId, "algId");

    if (algoNames.isEmpty()) {
      return true;
    }

    String name;
    try {
      name = AlgorithmUtil.getSignatureAlgoName(algId);
    } catch (NoSuchAlgorithmException ex) {
      return false;
    }

    return algoNames.contains(name);
  }

  @Override
  public boolean isAlgorithmPermitted(String algoName) {
    Args.notBlank(algoName, "algoName");

    if (algoNames.isEmpty()) {
      return true;
    }

    if (algoNames.contains(algoName)) {
      return true;
    }

    String name;
    try {
      name = AlgorithmUtil.canonicalizeSignatureAlgo(algoName);
    } catch (NoSuchAlgorithmException ex) {
      return false;
    }

    return algoNames.contains(name);
  }

}
