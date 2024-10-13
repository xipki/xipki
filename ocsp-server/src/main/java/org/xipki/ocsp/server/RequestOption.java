// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.security.HashAlgo;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.exception.InvalidConfException;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * OCSP request option.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class RequestOption {

  static final Set<HashAlgo> SUPPORTED_HASH_ALGORITHMS;

  static {
    SUPPORTED_HASH_ALGORITHMS = CollectionUtil.asSet(HashAlgo.SHA1,
        HashAlgo.SHA224,   HashAlgo.SHA256,   HashAlgo.SHA384,   HashAlgo.SHA512,
        HashAlgo.SHA3_224, HashAlgo.SHA3_256, HashAlgo.SHA3_384, HashAlgo.SHA3_512,
        HashAlgo.SHAKE128, HashAlgo.SHAKE256, HashAlgo.SM3);
  }

  private final boolean supportsHttpGet;

  private final int maxRequestListCount;

  private final int maxRequestSize;

  private final Collection<Integer> versions;

  private final QuadrupleState nonceOccurrence;

  private final int nonceMinLen;

  private final int nonceMaxLen;

  private final Set<HashAlgo> hashAlgos;

  RequestOption(OcspServerConf.RequestOption conf) throws InvalidConfException {
    supportsHttpGet = Args.notNull(conf, "conf").isSupportsHttpGet();

    // Request nonce
    OcspServerConf.Nonce nonceConf = conf.getNonce();
    nonceOccurrence = conf.getNonce().getOccurrence();

    nonceMinLen = nonceConf.getMinLen() != null ? nonceConf.getMinLen() : 4;

    nonceMaxLen = nonceConf.getMaxLen() != null ? nonceConf.getMaxLen() : 96;

    if (nonceMinLen < 0) {
      throw new InvalidConfException("invalid nonceMinLen (<1): " + nonceMinLen);
    }

    if (nonceMinLen > nonceMaxLen) {
      throw new InvalidConfException("nonceMinLen > nonceMaxLen");
    }

    maxRequestListCount = conf.getMaxRequestListCount();
    if (maxRequestListCount < 1) {
      throw new InvalidConfException("invalid maxRequestListCount " + maxRequestListCount);
    }

    maxRequestSize = conf.getMaxRequestSize();
    if (maxRequestSize < 100) {
      throw new InvalidConfException("invalid maxRequestSize " + maxRequestSize);
    }

    // Request versions

    versions = new HashSet<>();
    for (String m : conf.getVersions()) {
      if ("v1".equalsIgnoreCase(m)) {
        versions.add(0);
      } else {
        throw new InvalidConfException("invalid OCSP request version '" + m + "'");
      }
    }

    // Request hash algorithms
    hashAlgos = new HashSet<>();
    if (conf.getHashAlgorithms().isEmpty()) {
      hashAlgos.addAll(SUPPORTED_HASH_ALGORITHMS);
    } else {
      for (String token : conf.getHashAlgorithms()) {
        HashAlgo algo;
        try {
          algo = HashAlgo.getInstance(token);
        } catch (NoSuchAlgorithmException ex) {
          throw new InvalidConfException(ex.getMessage());
        }

        if (SUPPORTED_HASH_ALGORITHMS.contains(algo)) {
          hashAlgos.add(algo);
        } else {
          throw new InvalidConfException("hash algorithm " + token + " is unsupported");
        }
      }
    }
  } // constructor

  public Set<HashAlgo> getHashAlgos() {
    return hashAlgos;
  }

  public boolean supportsHttpGet() {
    return supportsHttpGet;
  }

  public QuadrupleState getNonceOccurrence() {
    return nonceOccurrence;
  }

  public int getMaxRequestListCount() {
    return maxRequestListCount;
  }

  public int getMaxRequestSize() {
    return maxRequestSize;
  }

  public int getNonceMinLen() {
    return nonceMinLen;
  }

  public int getNonceMaxLen() {
    return nonceMaxLen;
  }

  public boolean allows(HashAlgo hashAlgo) {
    return hashAlgo != null && hashAlgos.contains(hashAlgo);
  }

  public boolean isVersionAllowed(Integer version) {
    return versions == null || versions.contains(version);
  }

}
