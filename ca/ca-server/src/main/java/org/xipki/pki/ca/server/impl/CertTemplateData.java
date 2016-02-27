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

package org.xipki.pki.ca.server.impl;

import java.util.Date;

import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.xipki.commons.common.util.ParamUtil;

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

    public CertTemplateData(
            final X500Name subject,
            final SubjectPublicKeyInfo publicKeyInfo,
            final OptionalValidity validity,
            final Extensions extensions,
            final String certprofileName) {
        ParamUtil.assertNotNull("subject", subject);
        ParamUtil.assertNotNull("publicKeyInfo", publicKeyInfo);
        ParamUtil.assertNotBlank("certprofileName", certprofileName);

        this.subject = subject;
        this.publicKeyInfo = publicKeyInfo;
        this.extensions = extensions;
        this.certprofileName = certprofileName;

        Date lNotBefore = null;
        Date lNotAfter = null;
        if (validity != null) {
            Time t = validity.getNotBefore();
            if (t != null) {
                lNotBefore = t.getDate();
            }
            t = validity.getNotAfter();
            if (t != null) {
                lNotAfter = t.getDate();
            }
        }
        this.notBefore = lNotBefore;
        this.notAfter = lNotAfter;
    }

    public CertTemplateData(
            final X500Name subject,
            final SubjectPublicKeyInfo publicKeyInfo,
            final Date notBefore,
            final Date notAfter,
            final Extensions extensions,
            final String certprofileName) {
        ParamUtil.assertNotNull("subject", subject);
        ParamUtil.assertNotNull("publicKeyInfo", publicKeyInfo);
        ParamUtil.assertNotBlank("certprofileName", certprofileName);

        this.subject = subject;
        this.publicKeyInfo = publicKeyInfo;
        this.extensions = extensions;
        this.certprofileName = certprofileName;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public X500Name getSubject() {
        return subject;
    }

    public SubjectPublicKeyInfo getPublicKeyInfo() {
        return publicKeyInfo;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public String getCertprofileName() {
        return certprofileName;
    }

    public Extensions getExtensions() {
        return extensions;
    }

}
