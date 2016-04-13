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

package org.xipki.pki.ocsp.store.db.internal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import org.xipki.pki.ocsp.api.OcspStoreException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class StoreConf {

    private static final String KEY_cacerts_includes = "cacerts.includes";

    private static final String KEY_cacerts_excludes = "cacerts.excludes";

    private final Set<String> caCertsIncludes = new HashSet<>();

    private final Set<String> caCertsExcludes = new HashSet<>();

    StoreConf(
            final String propsConf)
    throws OcspStoreException {
        Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(propsConf.getBytes()));
        } catch (IOException ex) {
            throw new OcspStoreException("could not load properties: " + ex.getMessage(), ex);
        }

        String str = props.getProperty(KEY_cacerts_includes);
        if (str != null) {
            StringTokenizer st = new StringTokenizer(str, ", ");
            while (st.hasMoreTokens()) {
                caCertsIncludes.add(st.nextToken());
            }
        }

        str = props.getProperty(KEY_cacerts_excludes);
        if (str != null) {
            StringTokenizer st = new StringTokenizer(str, ", ");
            while (st.hasMoreTokens()) {
                caCertsExcludes.add(st.nextToken());
            }
        }
    }

    Set<String> getCaCertsIncludes() {
        return caCertsIncludes;
    }

    Set<String> getCaCertsExcludes() {
        return caCertsExcludes;
    }

}
