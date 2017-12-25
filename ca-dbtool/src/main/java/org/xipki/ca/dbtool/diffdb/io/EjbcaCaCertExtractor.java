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

package org.xipki.ca.dbtool.diffdb.io;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

import org.xipki.common.util.ParamUtil;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EjbcaCaCertExtractor {

    private EjbcaCaCertExtractor() {
    }

    public static X509Certificate extractCaCert(final String caData) throws Exception {
        ParamUtil.requireNonNull("caData", caData);

        XmlDocumentReader cadataReader = new XmlDocumentReader(
                new ByteArrayInputStream(caData.getBytes()), false);
        final String xpathCert =
                "/java/object/void[string[position()=1]='certificatechain']/object/void/string[1]";
        String b64Cert = cadataReader.value(xpathCert);
        if (b64Cert == null) {
            throw new Exception("Could not extract CA certificate");
        }

        return X509Util.parseBase64EncodedCert(b64Cert);
    }

}
