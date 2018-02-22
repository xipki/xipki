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

package org.xipki.ca.server.mgmt.api.x509;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.xipki.common.util.Base64;
import org.xipki.common.util.LogUtil;
import org.xipki.security.util.X509Util;

/**
 * For internal use only.
 * @author Lijun Liao
 */

class InternUtil {

  private InternUtil() {
  }

  static String formatCert(X509Certificate cert, boolean verbose) {
    if (cert == null) {
      return "\tnull";
    }

    StringBuilder sb = new StringBuilder(verbose ? 1000 : 100);
    sb.append("\tissuer: ")
      .append(X509Util.getRfc4519Name(cert.getIssuerX500Principal())).append('\n');
    sb.append("\tserialNumber: ").append(LogUtil.formatCsn(cert.getSerialNumber())).append('\n');
    sb.append("\tsubject: ")
      .append(X509Util.getRfc4519Name(cert.getSubjectX500Principal())).append('\n');
    sb.append("\tnotBefore: ").append(cert.getNotBefore()).append("\n");
    sb.append("\tnotAfter: ").append(cert.getNotAfter()).append("\n");

    if (verbose) {
      sb.append("\tencoded: ");
      try {
        sb.append(Base64.encodeToString(cert.getEncoded()));
      } catch (CertificateEncodingException ex) {
        sb.append("ERROR");
      }
    }

    return sb.toString();

  }

}
