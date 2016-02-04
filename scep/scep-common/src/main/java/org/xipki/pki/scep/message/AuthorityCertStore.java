/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.scep.message;

import java.security.cert.X509Certificate;

import org.xipki.pki.scep.crypto.KeyUsage;
import org.xipki.pki.scep.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class AuthorityCertStore {

  private final X509Certificate cACert;

  private final X509Certificate signatureCert;

  private final X509Certificate encryptionCert;

  private AuthorityCertStore(
      final X509Certificate cACert,
      final X509Certificate signatureCert,
      final X509Certificate encryptionCert) {
    this.cACert = cACert;
    this.signatureCert = signatureCert;
    this.encryptionCert = encryptionCert;
  }

  public X509Certificate getSignatureCert() {
    return signatureCert;
  }

  public X509Certificate getEncryptionCert() {
    return encryptionCert;
  }

  public X509Certificate getCACert() {
    return cACert;
  }

  public static AuthorityCertStore getInstance(
      final X509Certificate cACert,
      final X509Certificate... rACerts) {
    ParamUtil.assertNotNull("cACert", cACert);

    X509Certificate encryptionCert = null;
    X509Certificate signatureCert = null;

    if (rACerts == null || rACerts.length == 0) {
      signatureCert = cACert;
      encryptionCert = cACert;
    } else {
      for (X509Certificate cert : rACerts) {
        boolean[] keyusage = cert.getKeyUsage();
        if (hasKeyusage(keyusage, KeyUsage.keyEncipherment)) {
          if (encryptionCert != null) {
            throw new IllegalArgumentException(
                "Could not determine RA certificate for encryption");
          }
          encryptionCert = cert;
        }

        if (hasKeyusage(keyusage, KeyUsage.digitalSignature)
            || hasKeyusage(keyusage, KeyUsage.contentCommitment)) {
          if (signatureCert != null) {
            throw new IllegalArgumentException(
                "Could not determine RA certificate for signature");
          }
          signatureCert = cert;
        }
      }

      if (encryptionCert == null) {
        throw new IllegalArgumentException(
            "Could not determine RA certificate for encryption");
      }

      if (signatureCert == null) {
        throw new IllegalArgumentException(
            "Could not determine RA certificate for signature");
      }
    }

    return new AuthorityCertStore(cACert, signatureCert, encryptionCert);
  } // method getInstance

  private static boolean hasKeyusage(
      final boolean[] keyusage,
      final KeyUsage usage) {
    if (keyusage != null && keyusage.length > usage.getBit()) {
      return keyusage[usage.getBit()];
    }
    return false;
  }

}
