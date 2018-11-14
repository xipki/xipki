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

import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.CompareUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerEntry {

  private final String name;

  private final String type;

  private String conf;

  private boolean certFaulty;

  private boolean confFaulty;

  private final String base64Cert;

  private X509Certificate certificate;

  public SignerEntry(String name, String type, String conf, String base64Cert) {
    this.name = Args.toNonBlankLower(name, "name");
    this.type = Args.toNonBlankLower(type, "type");
    this.conf = conf;
    this.base64Cert = base64Cert;

    if (base64Cert == null) {
      return;
    }

    try {
      this.certificate = X509Util.parseCert(base64Cert.getBytes());
    } catch (Throwable th) {
      this.certFaulty = true;
    }
  }

  public String getName() {
    return name;
  }

  public String getType() {
    return type;
  }

  public void setConf(String conf) {
    this.conf = conf;
  }

  public String getConf() {
    return conf;
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public void setCertificate(X509Certificate certificate) {
    if (base64Cert != null) {
      throw new IllegalStateException("certificate is already specified by base64Cert");
    }
    this.certificate = certificate;
  }

  public String getBase64Cert() {
    return base64Cert;
  }

  public boolean isFaulty() {
    return confFaulty || certFaulty;
  }

  public void setConfFaulty(boolean confFaulty) {
    this.confFaulty = confFaulty;
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    return toString(verbose, true);
  }

  public String toString(boolean verbose, boolean ignoreSensitiveInfo) {
    StringBuilder sb = new StringBuilder(1000);
    sb.append("name: ").append(name).append('\n');
    sb.append("faulty: ").append(isFaulty()).append('\n');
    sb.append("type: ").append(type).append('\n');
    sb.append("conf: ");
    if (conf == null) {
      sb.append("null");
    } else {
      sb.append(InternUtil.signerConfToString(conf, verbose, ignoreSensitiveInfo));
    }
    sb.append('\n');
    sb.append("certificate: ").append("\n");
    if (certificate != null || base64Cert != null) {
      if (certificate != null) {
        sb.append("\tissuer: ").append(X509Util.getRfc4519Name(
            certificate.getIssuerX500Principal())).append('\n');
        sb.append("\tserialNumber: ")
            .append(LogUtil.formatCsn(certificate.getSerialNumber())).append('\n');
        sb.append("\tsubject: ").append(X509Util.getRfc4519Name(
            certificate.getSubjectX500Principal()));
      }
      if (verbose) {
        sb.append("\n\tencoded: ");
        try {
          sb.append(Base64.encodeToString(certificate.getEncoded()));
        } catch (CertificateEncodingException ex) {
          sb.append("ERROR");
        }
      }
    } else {
      sb.append("  null");
    }
    return sb.toString();
  } // method toString

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof SignerEntry)) {
      return false;
    }

    SignerEntry objB = (SignerEntry) obj;
    return name.equals(objB.name)
        && type.equals(objB.type)
        && CompareUtil.equalsObject(conf, objB.conf)
        && CompareUtil.equalsObject(base64Cert, objB.base64Cert);
  }

  @Override
  public int hashCode() {
    return name.hashCode();
  }

}
