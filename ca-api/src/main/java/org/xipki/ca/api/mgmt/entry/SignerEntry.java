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

package org.xipki.ca.api.mgmt.entry;

import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CompareUtil;
import org.xipki.util.StringUtil;

/**
 * Management Entry Signer.
 * @author Lijun Liao
 *
 */

public class SignerEntry extends MgmtEntry {

  private final String name;

  private final String type;

  private String conf;

  private boolean certFaulty;

  private boolean confFaulty;

  private final String base64Cert;

  private X509Cert certificate;

  public SignerEntry(String name, String type, String conf, String base64Cert) {
    this.name = Args.toNonBlankLower(name, "name");
    this.type = Args.toNonBlankLower(type, "type");
    this.conf = conf;
    this.base64Cert = base64Cert;

    if (base64Cert == null) {
      return;
    }

    try {
      this.certificate = X509Util.parseCert(StringUtil.toUtf8Bytes(base64Cert));
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

  public X509Cert getCertificate() {
    return certificate;
  }

  public void setCertificate(X509Cert certificate) {
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
      sb.append(signerConfToString(conf, verbose, ignoreSensitiveInfo));
    }
    sb.append('\n');
    sb.append("certificate: ").append("\n");
    if (certificate != null || base64Cert != null) {
      if (certificate != null) {
        sb.append("\tissuer: ").append(certificate.getIssuerRfc4519Text()).append('\n');
        sb.append("\tserialNumber: ").append(certificate.getSerialNumberHex()).append('\n');
        sb.append("\tsubject: ").append(certificate.getSubjectRfc4519Text());
      }
      if (verbose) {
        sb.append("\n\tencoded: ");
        sb.append(Base64.encodeToString(certificate.getEncoded()));
      }
    } else {
      sb.append("  null");
    }
    return sb.toString();
  } // method toString(boolean, boolean)

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
  } // method equals

  @Override
  public int hashCode() {
    return name.hashCode();
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
  } // method signerConfToString

} // class Signer
