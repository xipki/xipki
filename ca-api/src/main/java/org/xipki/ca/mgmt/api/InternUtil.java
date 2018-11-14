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

package org.xipki.ca.mgmt.api;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.xipki.security.SignerConf;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.LogUtil;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * For internal use only.
 * @author Lijun Liao
 */

class InternUtil {

  private InternUtil() {
  }

  static String formatCert(X509Certificate cert, boolean verbose) {
    if (cert == null) {
      return "  null";
    }

    StringBuilder sb = new StringBuilder(verbose ? 1000 : 100);
    sb.append("  issuer:  ")
      .append(X509Util.getRfc4519Name(cert.getIssuerX500Principal())).append('\n');
    sb.append("  serialNumber: ").append(LogUtil.formatCsn(cert.getSerialNumber())).append('\n');
    sb.append("  subject: ")
      .append(X509Util.getRfc4519Name(cert.getSubjectX500Principal())).append('\n');
    sb.append("  notBefore: ").append(cert.getNotBefore()).append("\n");
    sb.append("  notAfter:  ").append(cert.getNotAfter());

    if (verbose) {
      sb.append("\n  encoded: ");
      try {
        sb.append(Base64.encodeToString(cert.getEncoded()));
      } catch (CertificateEncodingException ex) {
        sb.append("ERROR");
      }
    }

    return sb.toString();
  }

  static String signerConfToString(String signerConf, boolean verbose,
      boolean ignoreSensitiveInfo) {
    Args.notBlank(signerConf, "signerConf");
    if (ignoreSensitiveInfo) {
      signerConf = SignerConf.eraseSensitiveData(signerConf);
    }

    if (verbose || signerConf.length() < 101) {
      return signerConf;
    } else {
      return StringUtil.concat(signerConf.substring(0, 97), "...");
    }
  }

}
