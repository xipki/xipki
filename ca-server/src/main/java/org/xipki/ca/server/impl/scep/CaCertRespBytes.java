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

package org.xipki.ca.server.impl.scep;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.xipki.common.util.ParamUtil;

/**
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaCertRespBytes {

    private final byte[] bytes;

    CaCertRespBytes(X509Certificate caCert, X509Certificate responderCert)
            throws CMSException, CertificateException {
        ParamUtil.requireNonNull("caCert", caCert);
        ParamUtil.requireNonNull("responderCert", responderCert);

        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        try {
            cmsSignedDataGen.addCertificate(new X509CertificateHolder(caCert.getEncoded()));
            cmsSignedDataGen.addCertificate(new X509CertificateHolder(responderCert.getEncoded()));
            CMSSignedData degenerateSignedData = cmsSignedDataGen.generate(new CMSAbsentContent());
            bytes = degenerateSignedData.getEncoded();
        } catch (IOException ex) {
            throw new CMSException("could not build CMS SignedDta");
        }
    }

    byte[] bytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

}
