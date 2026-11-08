// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.scep.message;

import org.xipki.codec.util.Args;
import org.xipki.pkix.cert.KeyUsage;
import org.xipki.pkix.cert.X509Cert;

/**
 * Authority Cert Store definition.
 *
 * @author Lijun Liao (xipki)
 */
public class AuthorityCertStore {

  private final X509Cert caCert;

  private final X509Cert signatureCert;

  private final X509Cert encryptionCert;

  private AuthorityCertStore(X509Cert caCert, X509Cert signatureCert, X509Cert encryptionCert) {
    this.caCert = caCert;
    this.signatureCert = signatureCert;
    this.encryptionCert = encryptionCert;
  }

  public X509Cert signatureCert() {
    return signatureCert;
  }

  public X509Cert encryptionCert() {
    return encryptionCert;
  }

  public X509Cert caCert() {
    return caCert;
  }

  public static AuthorityCertStore getInstance(X509Cert caCert, X509Cert... raCerts) {
    Args.notNull(caCert, "caCert");

    X509Cert encryptionCert = null;
    X509Cert signatureCert = null;

    if (raCerts == null || raCerts.length == 0) {
      signatureCert = caCert;
      encryptionCert = caCert;
    } else {
      for (X509Cert cert : raCerts) {
        if (allows(cert, KeyUsage.keyEncipherment)) {
          if (encryptionCert != null) {
            throw new IllegalArgumentException("Could not determine RA certificate for encryption");
          }
          encryptionCert = cert;
        }

        if (allows(cert, KeyUsage.digitalSignature)
            || allows(cert, KeyUsage.contentCommitment)) {
          if (signatureCert != null) {
            throw new IllegalArgumentException("Could not determine RA certificate for signature");
          }
          signatureCert = cert;
        }
      }

      if (encryptionCert == null) {
        throw new IllegalArgumentException("Could not determine RA certificate for encryption");
      }

      if (signatureCert == null) {
        throw new IllegalArgumentException("Could not determine RA certificate for signature");
      }
    }

    return new AuthorityCertStore(caCert, signatureCert, encryptionCert);
  }

  /**
   * Without the extension keyUsage, the key may be used for all purposes (RFC 5280).
   */
  private static boolean allows(X509Cert cert, KeyUsage usage) {
    return cert.keyUsage() == null || cert.hasKeyusage(usage);
  }

}
