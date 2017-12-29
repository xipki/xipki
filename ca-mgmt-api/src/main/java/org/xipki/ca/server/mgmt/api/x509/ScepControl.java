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

import org.xipki.common.ConfPairs;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.StringUtil;

/**
 *
 * Example configuration
 *
 * <pre>
 *
 * caCert.included?true%signerCert.included?false
 *
 * # Whether CA certificate is included in the response. Default is true
 * caCert.included=&lt;'true'|'false'&gt;
 *
 * # Whether CMS signer certificate is embedded in the CMS message. Default is true
 * signerCert.included=&lt;'true'|'false'&gt;
 *
 *</pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepControl {

    public static final String KEY_CACERT_INCLUDED = "caCert.included";

    public static final String KEY_SIGNERCERT_INCLUDED = "signerCert.included";

    public static final String KEY_SUPPORT_GETCRL = "support.getcrl";

    private boolean includeCaCert = true;

    private boolean includeSignerCert = true;

    private boolean supportGetCrl = false;

    public ScepControl(String conf) throws InvalidConfException {
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
    }

    public String conf() {
        ConfPairs pairs = new ConfPairs();
        pairs.putPair(KEY_CACERT_INCLUDED, Boolean.toString(includeCaCert));
        pairs.putPair(KEY_SIGNERCERT_INCLUDED, Boolean.toString(includeSignerCert));

        return pairs.getEncoded();
    }

    public boolean includeCaCert() {
        return includeCaCert;
    }

    public void setIncludeCaCert(boolean includeCaCert) {
        this.includeCaCert = includeCaCert;
    }

    public boolean includeSignerCert() {
        return includeSignerCert;
    }

    public void setIncludeSignerCert(boolean includeSignerCert) {
        this.includeSignerCert = includeSignerCert;
    }

    public boolean supportGetCrl() {
        return supportGetCrl;
    }

    public void setSupportGetCrl(boolean supportGetCrl) {
        this.supportGetCrl = supportGetCrl;
    }

    @Override
    public String toString() {
        return conf();
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ScepControl)) {
            return false;
        }

        ScepControl obj2 = (ScepControl) obj;
        if (includeCaCert != obj2.includeCaCert
                || includeSignerCert != obj2.includeSignerCert) {
            return false;
        }

        return true;
    }

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
    }

}
