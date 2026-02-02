// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.security.HashAlgo;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.security.verify.CertPathValidationModel;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.io.FileOrBinary;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * OCSP request option.
 *
 * @author Lijun Liao (xipki)
 */

public class RequestOption {

  static final Set<HashAlgo> SUPPORTED_HASH_ALGORITHMS;

  static {
    SUPPORTED_HASH_ALGORITHMS = CollectionUtil.asSet(
        HashAlgo.SHA1,
        HashAlgo.SHA224,   HashAlgo.SHA256,
        HashAlgo.SHA384,   HashAlgo.SHA512,
        HashAlgo.SHA3_224, HashAlgo.SHA3_256,
        HashAlgo.SHA3_384, HashAlgo.SHA3_512,
        HashAlgo.SHAKE128, HashAlgo.SHAKE256,
        HashAlgo.SM3);
  }

  private final boolean supportsHttpGet;

  private final boolean signatureRequired;

  private final boolean validateSignature;

  private final int maxRequestListCount;

  private final int maxRequestSize;

  private final Collection<Integer> versions;

  private final QuadrupleState nonceOccurrence;

  private final int nonceMinLen;

  private final int nonceMaxLen;

  private final Set<HashAlgo> hashAlgos;

  private final Set<X509Cert> trustanchors;

  private final Set<X509Cert> certs;

  private final CertPathValidationModel certpathValidationModel;

  RequestOption(OcspServerConf.RequestOption conf) throws InvalidConfException {
    supportsHttpGet = Args.notNull(conf, "conf").isSupportsHttpGet();
    signatureRequired = conf.isSignatureRequired();
    validateSignature = conf.isValidateSignature();

    // Request nonce
    OcspServerConf.Nonce nonceConf = conf.nonce();
    nonceOccurrence = conf.nonce().occurrence();

    nonceMinLen = nonceConf.minLen() != null ? nonceConf.minLen() : 4;

    nonceMaxLen = nonceConf.maxLen() != null ? nonceConf.maxLen() : 96;

    if (nonceMinLen < 0) {
      throw new InvalidConfException(
          "invalid nonceMinLen (<1): " + nonceMinLen);
    }

    if (nonceMinLen > nonceMaxLen) {
      throw new InvalidConfException("nonceMinLen > nonceMaxLen");
    }

    maxRequestListCount = conf.maxRequestListCount();
    if (maxRequestListCount < 1) {
      throw new InvalidConfException(
          "invalid maxRequestListCount " + maxRequestListCount);
    }

    maxRequestSize = conf.maxRequestSize();
    if (maxRequestSize < 100) {
      throw new InvalidConfException(
          "invalid maxRequestSize " + maxRequestSize);
    }

    // Request versions

    versions = new HashSet<>();
    for (String m : conf.versions()) {
      if ("v1".equalsIgnoreCase(m)) {
        versions.add(0);
      } else {
        throw new InvalidConfException(
            "invalid OCSP request version '" + m + "'");
      }
    }

    // Request hash algorithms
    hashAlgos = new HashSet<>();
    if (conf.hashAlgorithms().isEmpty()) {
      hashAlgos.addAll(SUPPORTED_HASH_ALGORITHMS);
    } else {
      for (String token : conf.hashAlgorithms()) {
        HashAlgo algo;
        try {
          algo = HashAlgo.getInstance(token);
        } catch (NoSuchAlgorithmException ex) {
          throw new InvalidConfException(ex.getMessage());
        }

        if (SUPPORTED_HASH_ALGORITHMS.contains(algo)) {
          hashAlgos.add(algo);
        } else {
          throw new InvalidConfException(
              "hash algorithm " + token + " is unsupported");
        }
      }
    }

    // certpath validation
    OcspServerConf.CertpathValidation certpathConf =
        conf.certpathValidation();
    if (certpathConf == null) {
      if (validateSignature) {
        throw new InvalidConfException("certpathValidation is not specified");
      }
      trustanchors = null;
      certs = null;
      certpathValidationModel = CertPathValidationModel.PKIX;
      return;
    }

    certpathValidationModel = certpathConf.validationModel();

    try {
      Set<X509Cert> tmpCerts = getCerts(certpathConf.trustanchors());
      trustanchors = new HashSet<>(tmpCerts.size());
      trustanchors.addAll(tmpCerts);
    } catch (Exception ex) {
      throw new InvalidConfException("could not initialize the trustanchors: "
          + ex.getMessage(), ex);
    }

    OcspServerConf.CertCollection certsType = certpathConf.certs();
    try {
      certs = (certsType == null) ? null : getCerts(certsType);
    } catch (Exception ex) {
      throw new InvalidConfException(
          "could not initialize the certs: " + ex.getMessage(), ex);
    }
  } // constructor

  public Set<HashAlgo> hashAlgos() {
    return hashAlgos;
  }

  public boolean isSignatureRequired() {
    return signatureRequired;
  }

  public boolean isValidateSignature() {
    return validateSignature;
  }

  public boolean supportsHttpGet() {
    return supportsHttpGet;
  }

  public QuadrupleState nonceOccurrence() {
    return nonceOccurrence;
  }

  public int maxRequestListCount() {
    return maxRequestListCount;
  }

  public int maxRequestSize() {
    return maxRequestSize;
  }

  public int nonceMinLen() {
    return nonceMinLen;
  }

  public int nonceMaxLen() {
    return nonceMaxLen;
  }

  public boolean allows(HashAlgo hashAlgo) {
    return hashAlgo != null && hashAlgos.contains(hashAlgo);
  }

  public CertPathValidationModel certpathValidationModel() {
    return certpathValidationModel;
  }

  public Set<X509Cert> trustanchors() {
    return trustanchors;
  }

  public boolean isVersionAllowed(Integer version) {
    return versions == null || versions.contains(version);
  }

  public Set<X509Cert> certs() {
    return certs;
  }

  private static Set<X509Cert> getCerts(OcspServerConf.CertCollection conf)
      throws CertificateException, IOException {
    Args.notNull(conf, "conf");
    Set<X509Cert> tmpCerts = new HashSet<>();

    if (conf.certs() != null) {
      for (FileOrBinary fn : conf.certs()) {
        tmpCerts.add(X509Util.parseCert(fn.readContent()));
      }
    } else if (conf.dir() != null) {
      File dir = new File(conf.dir());
      File[] files = dir.listFiles();
      if (files != null) {
        for (File file : files) {
          if (file.exists() && file.isFile()) {
            tmpCerts.add(X509Util.parseCert(file));
          }
        }
      }
    } else {
      throw new IllegalStateException(
          "should not happen, neither keystore nor dir is defined");
    }

    return tmpCerts;
  } // method getCerts

}
