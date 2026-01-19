// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.misc.StringUtil;

import java.security.cert.CertificateEncodingException;

/**
 * Management Entry Signer.
 * @author Lijun Liao (xipki)
 *
 */

public class SignerEntry extends MgmtEntry {

  private final String name;

  private final String type;

  private String conf;

  private boolean faulty;

  private String base64Cert;

  private X509Cert certificate;

  private ConcurrentContentSigner signer;

  public ConcurrentContentSigner signer() {
    return signer;
  }

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
      this.faulty = true;
    }
  }

  public void initSigner(SecurityFactory securityFactory)
      throws ObjectCreationException {
    Args.notNull(securityFactory, "securityFactory");
    if (signer != null) {
      return;
    }

    faulty = true;
    signer = securityFactory.createSigner(type,
        new SignerConf(conf), certificate);
    if (signer.getCertificate() == null) {
      throw new ObjectCreationException(
          "signer without certificate is not allowed");
    }
    faulty = false;

    if (certificate == null) {
      setCertificate(signer.getCertificate());
    }
  } // method initSigner

  public boolean signerIsHealthy() {
    return signer != null && signer.isHealthy();
  }

  public void setCertificate(X509Cert certificate) {
    if (base64Cert != null) {
      throw new IllegalStateException(
          "certificate is already specified by base64Cert");
    }
    this.certificate = certificate;
    this.base64Cert = (certificate == null) ? null
        : Base64.encodeToString(certificate.getEncoded());
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

  public boolean isFaulty() {
    return faulty;
  }

  public void setFaulty(boolean faulty) {
    this.faulty = faulty;
  }

  public String base64Cert() {
    return base64Cert;
  }

  public X509Cert getCertificate() {
    return certificate;
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
    sb.append("name:   ").append(name).append('\n');
    sb.append("faulty: ").append(faulty).append('\n');
    sb.append("type:   ").append(type).append('\n');
    sb.append("conf:   ");
    if (conf == null) {
      sb.append("null");
    } else {
      sb.append(signerConfToString(conf, verbose, ignoreSensitiveInfo));
    }
    sb.append('\n');
    sb.append("cert:   ").append("\n");
    if (certificate != null || base64Cert != null) {
      if (certificate != null) {
        sb.append(X509Util.formatCert(certificate, verbose));
      } else {
        sb.append("  encoded: ").append(base64Cert);
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
        && CompareUtil.equals(conf, objB.conf)
        && CompareUtil.equals(base64Cert, objB.base64Cert);
  } // method equals

  @Override
  public int hashCode() {
    return name.hashCode();
  }

  static String signerConfToString(
      String signerConf, boolean verbose, boolean ignoreSensitiveInfo) {
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

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap()
        .put("name", name).put("type", type).put("conf", conf);

    if (certificate != null) {
      ret.put("certificate", certificate.getEncoded());
    }
    return ret;
  }

  public static SignerEntry parse(JsonMap json) throws CodecException {
    SignerEntry ret = new SignerEntry(json.getNnString("name"),
        json.getNnString("type"), json.getString("conf"),
        null);

    byte[] bytes = json.getBytes("certificate");
    if (bytes != null) {
      X509Cert cert;
      try {
        cert = X509Util.parseCert(bytes);
      } catch (CertificateEncodingException e) {
        throw new CodecException(e);
      }
      ret.setCertificate(cert);
    }

    return ret;
  }

}
