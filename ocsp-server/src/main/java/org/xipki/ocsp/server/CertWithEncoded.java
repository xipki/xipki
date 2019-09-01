/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.xipki.util.Args;

/**
 * Certificate wrapper with encoded content.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertWithEncoded {

  private final X509Certificate cert;

  private final String className;

  private final byte[] encoded;

  public CertWithEncoded(X509Certificate cert) throws CertificateEncodingException {
    this.cert = Args.notNull(cert, "cert");
    this.className = cert.getClass().getName();
    this.encoded = cert.getEncoded();
  }

  public X509Certificate getCert() {
    return cert;
  }

  public boolean equalsCert(X509Certificate cert) {
    if (cert == null) {
      return false;
    }
    if (this.cert == cert) {
      return true;
    }

    if (className.equals(cert.getClass().getName())) {
      return this.cert.equals(cert);
    } else if (this.cert.equals(cert)) {
      return true;
    } else {
      byte[] encodedCert;
      try {
        encodedCert = cert.getEncoded();
      } catch (CertificateEncodingException ex) {
        return false;
      }
      return Arrays.equals(encoded, encodedCert);
    }
  } // method equalsCert

}
