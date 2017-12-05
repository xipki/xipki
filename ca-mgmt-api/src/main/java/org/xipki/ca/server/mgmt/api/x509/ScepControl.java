/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
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

    public ScepControl(final String conf) throws InvalidConfException {
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

    public void setIncludeCaCert(final boolean includeCaCert) {
        this.includeCaCert = includeCaCert;
    }

    public boolean includeSignerCert() {
        return includeSignerCert;
    }

    public void setIncludeSignerCert(final boolean includeSignerCert) {
        this.includeSignerCert = includeSignerCert;
    }

    public boolean supportGetCrl() {
        return supportGetCrl;
    }

    public void setSupportGetCrl(final boolean supportGetCrl) {
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
    public boolean equals(final Object obj) {
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

    private static boolean getBoolean(final ConfPairs props, final String propKey,
            final boolean dfltValue) throws InvalidConfException {
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
