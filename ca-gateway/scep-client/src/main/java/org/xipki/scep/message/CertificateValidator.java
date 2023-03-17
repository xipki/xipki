// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.message;

import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

import java.util.Collection;
import java.util.HashSet;

/**
 * Certificate validator.
 *
 * @author Lijun Liao (xipki)
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
