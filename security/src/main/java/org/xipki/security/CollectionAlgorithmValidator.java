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

package org.xipki.security;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.xipki.util.Args.notNull;

/**
 * An implementation of {@link AlgorithmValidator} where the permitted algorithms
 * are contained in a static collection.
 *
 * @author Lijun Liao
 * @since 2.1.0
 */

public class CollectionAlgorithmValidator implements AlgorithmValidator {

  private final Set<SignAlgo> algos;

  private final Set<String> algoNames;

  /**
   * constructor.
   * @param algos algorithms that can be accepted. <code>null</code> or empty to accept
   *            all algorithms
   */
  public CollectionAlgorithmValidator(Collection<SignAlgo> algos) {
    this.algos = Collections.unmodifiableSet(new HashSet<>(algos));
    Set<String> names = new HashSet<>();
    for (SignAlgo m : algos) {
      names.add(m.getJceName());
    }
    this.algoNames = Collections.unmodifiableSet(names);
  }

  public Set<SignAlgo> getAlgos() {
    return algos;
  }

  public Set<String> getAlgoNames() {
    return algoNames;
  }

  @Override
  public boolean isAlgorithmPermitted(AlgorithmIdentifier algId) {
    notNull(algId, "algId");

    if (algos.isEmpty()) {
      return true;
    }

    SignAlgo algo;
    try {
      algo = SignAlgo.getInstance(algId);
    } catch (NoSuchAlgorithmException ex) {
      return false;
    }

    return algos.contains(algo);
  }

  @Override
  public boolean isAlgorithmPermitted(SignAlgo algo) {
    notNull(algo, "algo");
    return algos.contains(algo);
  }

}
