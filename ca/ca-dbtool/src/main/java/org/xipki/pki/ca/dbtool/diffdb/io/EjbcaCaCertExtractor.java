/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.ca.dbtool.diffdb.io;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EjbcaCaCertExtractor {

    private EjbcaCaCertExtractor() {
    }

    public static X509Certificate extractCaCert(
            final String caData)
    throws Exception {
        ParamUtil.requireNonNull("caData", caData);

        XmlDocumentReader cadataReader = new XmlDocumentReader(
                new ByteArrayInputStream(caData.getBytes()), false);
        final String xpathCert =
                "/java/object/void[string[position()=1]='certificatechain']/object/void/string[1]";
        String b64Cert = cadataReader.getValue(xpathCert);
        if (b64Cert == null) {
            throw new Exception("Could not extract CA certificate");
        }

        return X509Util.parseBase64EncodedCert(b64Cert);
    }

}
