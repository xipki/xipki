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

package org.xipki.scep.message;

import java.util.Collection;
import java.util.HashSet;

import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

/**
 * Certificate validator.
 *
 * @author Lijun Liao
 */

public interface CertificateValidator {

  /**
   * Whether the target certificate can be trusted.
   *
   * @param target
   *          The certificate to be verified. Must not be {@code null}.
   * @param otherCerts
   *          Additional certificate that may be used. Could be {@code null}.
   * @return whether the target certificate is trusted.
   */
  boolean trustCertificate(X509Cert target, X509Cert[] otherCerts);

  class CollectionCertificateValidator implements CertificateValidator {

    private final Collection<String> certHashes;

    public CollectionCertificateValidator(Collection<X509Cert> certs) {
      Args.notEmpty(certs, "certs");

      certHashes = new HashSet<>(certs.size());
      for (X509Cert cert : certs) {
        String hash = HashAlgo.SHA256.hexHash(cert.getEncoded());
        certHashes.add(hash);
      }
    }

    public CollectionCertificateValidator(X509Cert cert) {
      Args.notNull(cert, "cert");

      certHashes = new HashSet<>(2);
      String hash = HashAlgo.SHA256.hexHash(cert.getEncoded());
      certHashes.add(hash);
    }

    @Override
    public boolean trustCertificate(X509Cert signerCert, X509Cert[] otherCerts) {
      Args.notNull(signerCert, "signerCert");

      String hash = HashAlgo.SHA256.hexHash(signerCert.getEncoded());
      return certHashes.contains(hash);
    }

  } // class CollectionCertificateValidator

  class TrustAllCertValidator implements CertificateValidator {

    public boolean trustCertificate(X509Cert target, X509Cert[] otherCerts) {
      return true;
    }

  } // class TrustAllCertValidator

}
