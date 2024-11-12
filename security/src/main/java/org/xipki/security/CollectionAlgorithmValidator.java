// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.Args;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * An implementation of {@link AlgorithmValidator} where the permitted algorithms
 * are contained in a static collection.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class CollectionAlgorithmValidator implements AlgorithmValidator {

  private static final Logger LOG = LoggerFactory.getLogger(CollectionAlgorithmValidator.class);

  public static final CollectionAlgorithmValidator INSTANCE;

  private final Set<SignAlgo> algos;

  private final Set<String> algoNames;

  static {
    List<SignAlgo> secureAlgos = new ArrayList<>(SignAlgo.values().length);
    for (SignAlgo m : SignAlgo.values()) {
      if (m.getHashAlgo() != HashAlgo.SHA1) {
        secureAlgos.add(m);
      }
    }
    INSTANCE = new CollectionAlgorithmValidator(secureAlgos);
  }

  public static CollectionAlgorithmValidator buildAlgorithmValidator(Collection<String> algoNames)
      throws NoSuchAlgorithmException {
    Set<SignAlgo> algos = new HashSet<>();
    for (String algoName : algoNames) {
      SignAlgo sa;
      try {
        sa = SignAlgo.getInstance(algoName);
      } catch (NoSuchAlgorithmException ex) {
        LOG.warn("algorithm is not supported {}, ignore it", algoName);
        continue;
      }

      algos.add(sa);
    }

    if (algos.isEmpty()) {
      throw new NoSuchAlgorithmException("none of the signature algorithms " + algoNames + " are supported");
    }

    return new CollectionAlgorithmValidator(algos);
  }

  /**
   * constructor.
   * @param algos algorithms that can be accepted. <code>null</code> or empty to accept
   *            all algorithms
   */
  public CollectionAlgorithmValidator(Collection<SignAlgo> algos) {
    this.algos = Set.copyOf(algos);
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
    if (algos.isEmpty()) {
      return true;
    }

    SignAlgo algo;
    try {
      algo = SignAlgo.getInstance(Args.notNull(algId, "algId"));
    } catch (NoSuchAlgorithmException ex) {
      return false;
    }

    return algos.contains(algo);
  }

  @Override
  public boolean isAlgorithmPermitted(SignAlgo algo) {
    return algos.contains(Args.notNull(algo, "algo"));
  }

}
