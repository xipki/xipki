/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.server.impl;

import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertTemplateData {

    private final X500Name subject;
    private final SubjectPublicKeyInfo publicKeyInfo;
    private final Date notBefore;
    private final Date notAfter;
    private final String certprofileName;
    private final Extensions extensions;

    public CertTemplateData(final X500Name subject, final SubjectPublicKeyInfo publicKeyInfo,
            final Date notBefore, final Date notAfter, final Extensions extensions,
            final String certprofileName) {
        this.subject = ParamUtil.requireNonNull("subject", subject);
        this.publicKeyInfo = ParamUtil.requireNonNull("publicKeyInfo", publicKeyInfo);
        this.certprofileName = ParamUtil.requireNonBlank("certprofileName", certprofileName)
                .toUpperCase();
        this.extensions = extensions;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public X500Name subject() {
        return subject;
    }

    public SubjectPublicKeyInfo publicKeyInfo() {
        return publicKeyInfo;
    }

    public Date notBefore() {
        return notBefore;
    }

    public Date notAfter() {
        return notAfter;
    }

    public String certprofileName() {
        return certprofileName;
    }

    public Extensions extensions() {
        return extensions;
    }

}
