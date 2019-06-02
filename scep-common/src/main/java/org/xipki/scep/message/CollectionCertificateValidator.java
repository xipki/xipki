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

package org.xipki.scep.message;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;

import org.xipki.scep.crypto.ScepHashAlgo;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CollectionCertificateValidator implements CertificateValidator {

  private final Collection<String> certHashes;

  public CollectionCertificateValidator(Collection<X509Certificate> certs) {
    ScepUtil.requireNonEmpty("certs", certs);

    certHashes = new HashSet<String>(certs.size());
    for (X509Certificate cert : certs) {
      String hash;
      try {
        hash = ScepHashAlgo.SHA256.hexDigest(cert.getEncoded());
      } catch (CertificateEncodingException ex) {
        throw new IllegalArgumentException("could not encode certificate: " + ex.getMessage(), ex);
      }
      certHashes.add(hash);
    }
  }

  public CollectionCertificateValidator(X509Certificate cert) {
    ScepUtil.requireNonNull("cert", cert);

    certHashes = new HashSet<String>(2);
    String hash;
    try {
      hash = ScepHashAlgo.SHA256.hexDigest(cert.getEncoded());
    } catch (CertificateEncodingException ex) {
      throw new IllegalArgumentException("could not encode certificate: " + ex.getMessage(), ex);
    }
    certHashes.add(hash);
  }

  @Override
  public boolean trustCertificate(X509Certificate signerCert, X509Certificate[] otherCerts) {
    ScepUtil.requireNonNull("signerCert", signerCert);

    String hash;
    try {
      hash = ScepHashAlgo.SHA256.hexDigest(signerCert.getEncoded());
    } catch (CertificateEncodingException ex) {
      throw new IllegalArgumentException("could not encode certificate: " + ex.getMessage(), ex);
    }
    return certHashes.contains(hash);
  }

}
