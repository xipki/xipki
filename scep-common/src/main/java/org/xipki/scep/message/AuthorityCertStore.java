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

import java.security.cert.X509Certificate;

import org.xipki.scep.crypto.KeyUsage;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class AuthorityCertStore {

  private final X509Certificate caCert;

  private final X509Certificate signatureCert;

  private final X509Certificate encryptionCert;

  private AuthorityCertStore(X509Certificate caCert, X509Certificate signatureCert,
      X509Certificate encryptionCert) {
    this.caCert = caCert;
    this.signatureCert = signatureCert;
    this.encryptionCert = encryptionCert;
  }

  public X509Certificate getSignatureCert() {
    return signatureCert;
  }

  public X509Certificate getEncryptionCert() {
    return encryptionCert;
  }

  public X509Certificate getCaCert() {
    return caCert;
  }

  public static AuthorityCertStore getInstance(X509Certificate caCert, X509Certificate... raCerts) {
    ScepUtil.requireNonNull("caCert", caCert);

    X509Certificate encryptionCert = null;
    X509Certificate signatureCert = null;

    if (raCerts == null || raCerts.length == 0) {
      signatureCert = caCert;
      encryptionCert = caCert;
    } else {
      for (X509Certificate cert : raCerts) {
        boolean[] keyusage = cert.getKeyUsage();
        if (hasKeyusage(keyusage, KeyUsage.keyEncipherment)) {
          if (encryptionCert != null) {
            throw new IllegalArgumentException("Could not determine RA certificate for encryption");
          }
          encryptionCert = cert;
        }

        if (hasKeyusage(keyusage, KeyUsage.digitalSignature)
            || hasKeyusage(keyusage, KeyUsage.contentCommitment)) {
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

  private static boolean hasKeyusage(boolean[] keyusage, KeyUsage usage) {
    if (keyusage != null && keyusage.length > usage.getBit()) {
      return keyusage[usage.getBit()];
    }
    return false;
  }

}
