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

import org.xipki.security.KeyUsage;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

/**
 * Contains the CA certificate and the corresponding RA certificates, if exists.
 *
 * @author Lijun Liao
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

  public X509Cert getSignatureCert() {
    return signatureCert;
  }

  public X509Cert getEncryptionCert() {
    return encryptionCert;
  }

  public X509Cert getCaCert() {
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
        if (cert.hasKeyusage(KeyUsage.keyEncipherment)) {
          if (encryptionCert != null) {
            throw new IllegalArgumentException("Could not determine RA certificate for encryption");
          }
          encryptionCert = cert;
        }

        if (cert.hasKeyusage(KeyUsage.digitalSignature) || cert.hasKeyusage(KeyUsage.contentCommitment)) {
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
  } // method getInstance

}
