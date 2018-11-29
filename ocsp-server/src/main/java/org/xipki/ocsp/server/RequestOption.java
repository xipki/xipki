/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ocsp.server;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.xipki.ocsp.server.conf.CertCollectionType;
import org.xipki.ocsp.server.conf.NonceType;
import org.xipki.ocsp.server.conf.RequestOptionType;
import org.xipki.ocsp.server.conf.CertCollectionType.Keystore;
import org.xipki.ocsp.server.conf.RequestOptionType.CertpathValidation;
import org.xipki.security.CertpathValidationModel;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.IoUtil;
import org.xipki.util.Args;
import org.xipki.util.TripleState;
import org.xipki.util.conf.InvalidConfException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestOption {

  static final Set<HashAlgo> SUPPORTED_HASH_ALGORITHMS = new HashSet<>();

  static {
    SUPPORTED_HASH_ALGORITHMS.add(HashAlgo.SHA1);
    SUPPORTED_HASH_ALGORITHMS.add(HashAlgo.SHA224);
    SUPPORTED_HASH_ALGORITHMS.add(HashAlgo.SHA256);
    SUPPORTED_HASH_ALGORITHMS.add(HashAlgo.SHA384);
    SUPPORTED_HASH_ALGORITHMS.add(HashAlgo.SHA512);
    SUPPORTED_HASH_ALGORITHMS.add(HashAlgo.SHA3_224);
    SUPPORTED_HASH_ALGORITHMS.add(HashAlgo.SHA3_256);
    SUPPORTED_HASH_ALGORITHMS.add(HashAlgo.SHA3_384);
    SUPPORTED_HASH_ALGORITHMS.add(HashAlgo.SHA3_512);
  }

  private final boolean supportsHttpGet;

  private final boolean signatureRequired;

  private final boolean validateSignature;

  private final int maxRequestListCount;

  private final int maxRequestSize;

  private final Collection<Integer> versions;

  private final TripleState nonceOccurrence;

  private final int nonceMinLen;

  private final int nonceMaxLen;

  private final Set<HashAlgo> hashAlgos;

  private final Set<CertWithEncoded> trustAnchors;

  private final Set<X509Certificate> certs;

  private final CertpathValidationModel certpathValidationModel;

  RequestOption(RequestOptionType conf) throws InvalidConfException {
    Args.notNull(conf, "conf");

    supportsHttpGet = conf.isSupportsHttpGet();
    signatureRequired = conf.isSignatureRequired();
    validateSignature = conf.isValidateSignature();

    // Request nonce
    NonceType nonceConf = conf.getNonce();
    int minLen = 4;
    int maxLen = 32;
    String str = nonceConf.getOccurrence().toLowerCase();
    if ("forbidden".equals(str)) {
      nonceOccurrence = TripleState.forbidden;
    } else if ("optional".equals(str)) {
      nonceOccurrence = TripleState.optional;
    } else if ("required".equals(str)) {
      nonceOccurrence = TripleState.required;
    } else {
      throw new InvalidConfException("invalid nonce.occurrence '" + str
          + "', only forbidded, optional, and required are allowed");
    }

    if (nonceConf.getMinLen() != null) {
      minLen = nonceConf.getMinLen();
    }

    if (nonceConf.getMaxLen() != null) {
      maxLen = nonceConf.getMaxLen();
    }

    this.maxRequestListCount = conf.getMaxRequestListCount();
    if (this.maxRequestListCount < 1) {
      throw new InvalidConfException("invalid maxRequestListCount " + maxRequestListCount);
    }

    this.maxRequestSize = conf.getMaxRequestSize();
    if (this.maxRequestSize < 100) {
      throw new InvalidConfException("invalid maxRequestSize " + maxRequestSize);
    }

    this.nonceMinLen = minLen;
    this.nonceMaxLen = maxLen;

    // Request versions

    this.versions = new HashSet<>();
    for (String m : conf.getVersions()) {
      if ("v1".equalsIgnoreCase(m)) {
        this.versions.add(0);
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
        HashAlgo algo = HashAlgo.getInstance(token);
        if (algo != null && SUPPORTED_HASH_ALGORITHMS.contains(algo)) {
          hashAlgos.add(algo);
        } else {
          throw new InvalidConfException("hash algorithm " + token + " is unsupported");
        }
      }
    }

    // certpath validation
    CertpathValidation certpathConf = conf.getCertpathValidation();
    if (certpathConf == null) {
      if (validateSignature) {
        throw new InvalidConfException("certpathValidation is not specified");
      }
      trustAnchors = null;
      certs = null;
      certpathValidationModel = CertpathValidationModel.PKIX;
      return;
    }

    switch (certpathConf.getValidationModel()) {
      case CHAIN:
        certpathValidationModel = CertpathValidationModel.CHAIN;
        break;
      case PKIX:
        certpathValidationModel = CertpathValidationModel.PKIX;
        break;
      default:
        throw new IllegalStateException("should not reach here, unknown ValidationModel "
            + certpathConf.getValidationModel());
    } // end switch

    try {
      Set<X509Certificate> tmpCerts = getCerts(certpathConf.getTrustAnchors());
      trustAnchors = new HashSet<>(tmpCerts.size());
      for (X509Certificate m : tmpCerts) {
        trustAnchors.add(new CertWithEncoded(m));
      }
    } catch (Exception ex) {
      throw new InvalidConfException(
          "could not initialize the trustAnchors: " + ex.getMessage(), ex);
    }

    CertCollectionType certsType = certpathConf.getCerts();
    try {
      this.certs = (certsType == null) ? null : getCerts(certsType);
    } catch (Exception ex) {
      throw new InvalidConfException("could not initialize the certs: " + ex.getMessage(), ex);
    }
  } // constructor

  public Set<HashAlgo> getHashAlgos() {
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

  public TripleState getNonceOccurrence() {
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
    return (hashAlgo == null) ? false : hashAlgos.contains(hashAlgo);
  }

  public CertpathValidationModel getCertpathValidationModel() {
    return certpathValidationModel;
  }

  public Set<CertWithEncoded> getTrustAnchors() {
    return trustAnchors;
  }

  public boolean isVersionAllowed(Integer version) {
    return versions == null || versions.contains(version);
  }

  public Set<X509Certificate> getCerts() {
    return certs;
  }

  private static Set<X509Certificate> getCerts(CertCollectionType conf)
      throws KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException,
        CertificateException, IOException {
    Args.notNull(conf, "conf");
    Set<X509Certificate> tmpCerts = new HashSet<>();

    if (conf.getKeystore() != null) {
      Keystore ksConf = conf.getKeystore();
      KeyStore trustStore = KeyUtil.getKeyStore(ksConf.getType());

      String fileName = ksConf.getKeystore().getFile();
      InputStream is = (fileName != null)
          ? Files.newInputStream(Paths.get(IoUtil.expandFilepath(fileName)))
          : new ByteArrayInputStream(ksConf.getKeystore().getBinary());

      char[] password = (ksConf.getPassword() == null)  ? null
          : ksConf.getPassword().toCharArray();
      trustStore.load(is, password);

      Enumeration<String> aliases = trustStore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (trustStore.isCertificateEntry(alias)) {
          tmpCerts.add((X509Certificate) trustStore.getCertificate(alias));
        }
      }
    } else if (conf.getDir() != null) {
      File dir = new File(conf.getDir());
      File[] files = dir.listFiles();
      if (files != null) {
        for (File file : files) {
          if (file.exists() && file.isFile()) {
            tmpCerts.add(X509Util.parseCert(file));
          }
        }
      }
    } else {
      throw new IllegalStateException("should not happen, neither keystore nor dir is defined");
    }

    return tmpCerts;
  } // method getCerts

}
