// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;

import java.util.List;

/**
 * Configuration of {@link ConcurrentContentSigner}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class SignerConf {

  private final ConfPairs confPairs;

  private final HashAlgo hashAlgo;

  private final SignatureAlgoControl signatureAlgoControl;

  private List<X509Cert> peerCertificates;

  public SignerConf(String conf) {
    this(new ConfPairs(conf));
  }

  public SignerConf(ConfPairs conf) {
    this.hashAlgo = null;
    this.signatureAlgoControl = null;
    this.confPairs = Args.notNull(conf, "conf");
    if (getConfValue("algo") == null) {
      throw new IllegalArgumentException("conf must contain the entry 'algo'");
    }
  }

  public SignerConf(String confWithoutAlgo, SignatureAlgoControl signatureAlgoControl) {
    this(confWithoutAlgo, null, signatureAlgoControl);
  }

  public SignerConf(String confWithoutAlgo, HashAlgo hashAlgo, SignatureAlgoControl signatureAlgoControl) {
    this.hashAlgo = hashAlgo;
    this.signatureAlgoControl = signatureAlgoControl;
    this.confPairs = new ConfPairs(Args.notBlank(confWithoutAlgo, "confWithoutAlgo"));
    if (getConfValue("algo") != null) {
      throw new IllegalArgumentException("confWithoutAlgo may not contain the entry 'algo'");
    }
  }

  public HashAlgo getHashAlgo() {
    return hashAlgo;
  }

  public SignatureAlgoControl getSignatureAlgoControl() {
    return signatureAlgoControl;
  }

  public void putConfEntry(String name, String value) {
    confPairs.putPair(name, value);
  }

  public void removeConfEntry(String name) {
    confPairs.removePair(name);
  }

  public String getConfValue(String name) {
    return confPairs.value(name);
  }

  public ConfPairs getConf() {
    return confPairs;
  }

  public List<X509Cert> getPeerCertificates() {
    return peerCertificates;
  }

  public void setPeerCertificates(List<X509Cert> peerCertificates) {
    this.peerCertificates = peerCertificates;
  }

  @Override
  public String toString() {
    return toString(true, true);
  }

  public String toString(boolean verbose, boolean ignoreSensitiveInfo) {
    String txtConf;
    if (ignoreSensitiveInfo) {
      txtConf = eraseSensitiveData(confPairs);
    } else {
      txtConf = confPairs.toString();
    }

    StringBuilder sb = new StringBuilder(txtConf.length() + 50);
    sb.append("conf: ");
    sb.append(txtConf);
    if (hashAlgo != null) {
      sb.append("\nhash algo: ").append(hashAlgo.getJceName());
    }

    if (signatureAlgoControl != null) {
      sb.append("\nsiganture algo control: ").append(signatureAlgoControl);
    }

    sb.append("\npeerCertificates: ");
    if (CollectionUtil.isEmpty(peerCertificates)) {
      sb.append("null");
    } else {
      for (int i = 0; i < peerCertificates.size(); i++) {
        sb.append("\ncert[").append(i).append("]:\n");
        sb.append(X509Util.formatCert(peerCertificates.get(i), verbose));
      }
    }

    return sb.toString();
  } // method toString

  public static String eraseSensitiveData(ConfPairs conf) {
    if (conf == null) {
      return "";
    }

    try {
      return conf.toStringOmitSensitive("password");
    } catch (Exception ex) {
      return conf.toString();
    }
  } // method eraseSensitiveData

  public static String eraseSensitiveData(String conf) {
    if (conf == null || !conf.toLowerCase().contains("password")) {
      return conf;
    }

    try {
      return new ConfPairs(conf).toStringOmitSensitive("password");
    } catch (Exception ex) {
      return conf;
    }
  }

}
