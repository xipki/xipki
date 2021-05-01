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

package org.xipki.security;

import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

import java.util.List;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * Configuration of {@link ConcurrentContentSigner}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerConf {

  private final ConfPairs confPairs;

  private final HashAlgo hashAlgo;

  private final SignatureAlgoControl signatureAlgoControl;

  private List<X509Cert> peerCertificates;

  public SignerConf(String conf) {
    this.hashAlgo = null;
    this.signatureAlgoControl = null;
    this.confPairs = new ConfPairs(notBlank(conf, "conf"));
    if (getConfValue("algo") == null) {
      throw new IllegalArgumentException("conf must contain the entry 'algo'");
    }
  }

  public SignerConf(String confWithoutAlgo, HashAlgo hashAlgo,
      SignatureAlgoControl signatureAlgoControl) {
    this.hashAlgo = notNull(hashAlgo, "hashAlgo");
    this.signatureAlgoControl = signatureAlgoControl;
    this.confPairs = new ConfPairs(notBlank(confWithoutAlgo, "confWithoutAlgo"));
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

  public String getConf() {
    return confPairs.getEncoded();
  }

  public List<X509Cert> getPeerCertificates() {
    return peerCertificates;
  }

  public void setPeerCertificates(List<X509Cert> peerCertificates) {
    this.peerCertificates = peerCertificates;
  }

  public ConfPairs getConfPairs() {
    return confPairs;
  }

  @Override
  public String toString() {
    return toString(true, true);
  }

  public String toString(boolean verbose, boolean ignoreSensitiveInfo) {
    String conf = getConf();
    if (ignoreSensitiveInfo) {
      conf = eraseSensitiveData(conf);
    }

    StringBuilder sb = new StringBuilder(conf.length() + 50);
    sb.append("conf: ");
    sb.append(conf);
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

  public static String eraseSensitiveData(String conf) {
    if (conf == null || !conf.toLowerCase().contains("password")) {
      return conf;
    }

    try {
      ConfPairs pairs = new ConfPairs(conf);
      for (String name : pairs.names()) {
        if (name.toLowerCase().contains("password")) {
          String value = pairs.value(name);
          if (value != null && !StringUtil.startsWithIgnoreCase(value, "PBE:")) {
            pairs.putPair(name, "<sensitive>");
          }
        }
      }
      return pairs.getEncoded();
    } catch (Exception ex) {
      return conf;
    }
  } // method eraseSensitiveData

}
