/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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

package org.xipki.pki.ca.server.mgmt.api;

import java.io.Serializable;

import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;

/**
 *
 * Example configuration
 * caCert.included?true%signerCert.included?false
 *
 * # Whether CA certificate is included in the response. Default is true
 * caCert.included=<'true'|'false'>
 *
 * # Whether CMS signer certificate is embedded in the CMS message. Default is true
 * signerCert.included=<'true'|'false'>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepControl implements Serializable {

    public static final String KEY_CACERT_INCLUDED = "caCert.included";

    public static final String KEY_SIGNERCERT_INCLUDED = "signerCert.included";

    private static final long serialVersionUID = 1L;

    private boolean includeCaCert = true;

    private boolean includeSignerCert = true;

    public ScepControl(
            final String conf)
    throws InvalidConfException {
        if (StringUtil.isBlank(conf)) {
            return;
        }
        ParamUtil.assertNotBlank("conf", conf);
        ConfPairs props;
        try {
            props = new ConfPairs(conf);
        } catch (RuntimeException e) {
            throw new InvalidConfException(e.getClass().getName() + ": " + e.getMessage(), e);
        }

        this.includeCaCert = getBoolean(props, KEY_CACERT_INCLUDED, true);
        this.includeSignerCert = getBoolean(props, KEY_SIGNERCERT_INCLUDED, true);
    }

    public String getConf() {
        ConfPairs pairs = new ConfPairs();
        pairs.putPair(KEY_CACERT_INCLUDED, Boolean.toString(includeCaCert));
        pairs.putPair(KEY_SIGNERCERT_INCLUDED, Boolean.toString(includeSignerCert));

        return pairs.getEncoded();
    }

    public boolean isIncludeCaCert() {
        return includeCaCert;
    }

    public void setIncludeCaCert(
            final boolean includeCaCert) {
        this.includeCaCert = includeCaCert;
    }

    public boolean isIncludeSignerCert() {
        return includeSignerCert;
    }

    public void setIncludeSignerCert(
            final boolean includeSignerCert) {
        this.includeSignerCert = includeSignerCert;
    }

    @Override
    public String toString() {
        return getConf();
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    @Override
    public boolean equals(
            final Object obj) {
        if (!(obj instanceof ScepControl)) {
            return false;
        }

        ScepControl b = (ScepControl) obj;
        if (includeCaCert != b.includeCaCert
                || includeSignerCert != b.includeSignerCert) {
            return false;
        }

        return true;
    }

    private static boolean getBoolean(
            final ConfPairs props,
            final String propKey,
            final boolean dfltValue)
    throws InvalidConfException {
        String s = props.getValue(propKey);
        if (s != null) {
            s = s.trim();
            if ("true".equalsIgnoreCase(s)) {
                return Boolean.TRUE;
            } else if ("false".equalsIgnoreCase(s)) {
                return Boolean.FALSE;
            } else {
                throw new InvalidConfException(propKey + " does not have boolean value: " + s);
            }
        }
        return dfltValue;
    }

}
