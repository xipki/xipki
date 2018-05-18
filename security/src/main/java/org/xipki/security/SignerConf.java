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

package org.xipki.security;

import org.xipki.common.ConfPairs;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerConf {

  private final ConfPairs confPairs;

  private final HashAlgo hashAlgo;

  private final SignatureAlgoControl signatureAlgoControl;

  public SignerConf(String conf) {
    this.hashAlgo = null;
    this.signatureAlgoControl = null;
    ParamUtil.requireNonBlank("conf", conf);
    this.confPairs = new ConfPairs(conf);
    if (getConfValue("algo") == null) {
      throw new IllegalArgumentException("conf must contain the entry 'algo'");
    }
  }

  public SignerConf(String confWithoutAlgo, HashAlgo hashAlgo,
      SignatureAlgoControl signatureAlgoControl) {
    ParamUtil.requireNonBlank("confWithoutAlgo", confWithoutAlgo);
    this.hashAlgo = ParamUtil.requireNonNull("hashAlgo", hashAlgo);
    this.signatureAlgoControl = signatureAlgoControl;
    this.confPairs = new ConfPairs(confWithoutAlgo);
    if (getConfValue("algo") != null) {
      throw new IllegalArgumentException("confWithoutAlgo must not contain the entry 'algo'");
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
      sb.append("\nhash algo: ").append(hashAlgo.getName());
    }

    if (signatureAlgoControl != null) {
      sb.append("\nsiganture algo control: ").append(signatureAlgoControl);
    }

    return sb.toString();
  }

  public static String eraseSensitiveData(String conf) {
    if (conf == null || !conf.contains("password?")) {
      return conf;
    }

    try {
      ConfPairs pairs = new ConfPairs(conf);
      String value = pairs.value("password");
      if (value != null && !StringUtil.startsWithIgnoreCase(value, "PBE:")) {
        pairs.putPair("password", "<sensitive>");
      }
      return pairs.getEncoded();
    } catch (Exception ex) {
      return conf;
    }
  }

}
