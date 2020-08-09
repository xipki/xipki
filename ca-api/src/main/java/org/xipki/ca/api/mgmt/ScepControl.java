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

package org.xipki.ca.api.mgmt;

import org.xipki.util.ConfPairs;
import org.xipki.util.InvalidConfException;
import org.xipki.util.StringUtil;

/**
 * SCEP control.
 *
 * <p>Example configuration.
 *
 * <pre>
 *
 * cacert.included?true%signercert.included?false
 *
 * # Whether CA certificate is included in the response. Default is true
 * cacert.included=&lt;'true'|'false'&gt;
 *
 * # Whether CMS signer certificate is embedded in the CMS message. Default is true
 * signercert.included=&lt;'true'|'false'&gt;
 *
 *</pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepControl {

  public static final String KEY_CACERT_INCLUDED = "cacert.included";

  public static final String KEY_SIGNERCERT_INCLUDED = "signercert.included";

  public static final String KEY_SUPPORT_GETCRL = "support.getcrl";

  private boolean includeCaCert = true;

  private boolean includeSignerCert = true;

  private boolean supportGetCrl = false;

  public ScepControl(String conf)
      throws InvalidConfException {
    if (StringUtil.isBlank(conf)) {
      return;
    }

    ConfPairs props;
    try {
      props = new ConfPairs(conf);
    } catch (RuntimeException ex) {
      throw new InvalidConfException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
    }

    this.includeCaCert = getBoolean(props, KEY_CACERT_INCLUDED, true);
    this.includeSignerCert = getBoolean(props, KEY_SIGNERCERT_INCLUDED, true);
    this.supportGetCrl = getBoolean(props, KEY_SUPPORT_GETCRL, false);
  } // constructor

  public String getConf() {
    ConfPairs pairs = new ConfPairs();
    pairs.putPair(KEY_CACERT_INCLUDED, Boolean.toString(includeCaCert));
    pairs.putPair(KEY_SIGNERCERT_INCLUDED, Boolean.toString(includeSignerCert));
    pairs.putPair(KEY_SUPPORT_GETCRL, Boolean.toString(supportGetCrl));

    return pairs.getEncoded();
  }

  public boolean isIncludeCaCert() {
    return includeCaCert;
  }

  public void setIncludeCaCert(boolean includeCaCert) {
    this.includeCaCert = includeCaCert;
  }

  public boolean isIncludeSignerCert() {
    return includeSignerCert;
  }

  public void setIncludeSignerCert(boolean includeSignerCert) {
    this.includeSignerCert = includeSignerCert;
  }

  public boolean isSupportGetCrl() {
    return supportGetCrl;
  }

  public void setSupportGetCrl(boolean supportGetCrl) {
    this.supportGetCrl = supportGetCrl;
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    return StringUtil.concatObjects("  include CA cert: ", includeCaCert,
        "\n  include signer cert: ", includeSignerCert,
        "\n  operation GetCRL: ", (supportGetCrl ? "supported" : "not supported"),
        (verbose ? "\n  encoded: " : ""), (verbose ? getConf() : ""));
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof ScepControl)) {
      return false;
    }

    ScepControl obj2 = (ScepControl) obj;
    if (includeCaCert != obj2.includeCaCert || includeSignerCert != obj2.includeSignerCert) {
      return false;
    }

    return true;
  } // method equals

  private static boolean getBoolean(ConfPairs props, String propKey, boolean dfltValue)
      throws InvalidConfException {
    String str = props.value(propKey);
    if (str != null) {
      str = str.trim();
      if ("true".equalsIgnoreCase(str)) {
        return Boolean.TRUE;
      } else if ("false".equalsIgnoreCase(str)) {
        return Boolean.FALSE;
      } else {
        throw new InvalidConfException(propKey + " does not have boolean value: " + str);
      }
    }
    return dfltValue;
  } // method getBoolean

}
