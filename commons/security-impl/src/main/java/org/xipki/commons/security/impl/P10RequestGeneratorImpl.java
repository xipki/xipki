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

package org.xipki.commons.security.impl;

import java.security.cert.X509Certificate;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.xipki.commons.common.ObjectCreationException;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.NoIdleSignerException;
import org.xipki.commons.security.api.P10RequestGenerator;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P10RequestGeneratorImpl implements P10RequestGenerator {

    @Override
    public PKCS10CertificationRequest generateRequest(
            final SecurityFactory securityFactory,
            final String signerType,
            final String signerConf,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final String subject,
            final Map<ASN1ObjectIdentifier, ASN1Encodable> attributes)
    throws PasswordResolverException, SecurityException {
        ParamUtil.requireNonNull("subject", subject);
        X500Name subjectDn = new X500Name(subject);
        return generateRequest(securityFactory, signerType, signerConf, subjectPublicKeyInfo,
                subjectDn, attributes);
    }

    @Override
    public PKCS10CertificationRequest generateRequest(
            final SecurityFactory securityFactory,
            final String signerType,
            final String signerConf,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final X500Name subjectDn,
            final Map<ASN1ObjectIdentifier, ASN1Encodable> attributes)
    throws SecurityException {
        ParamUtil.requireNonNull("securityFactory", securityFactory);
        ParamUtil.requireNonNull("signerType", signerType);
        ConcurrentContentSigner signer;
        try {
            signer = securityFactory.createSigner(signerType, signerConf,
                    (X509Certificate[]) null);
        } catch (ObjectCreationException ex) {
            throw new SecurityException("could not create signer: " + ex.getMessage(), ex);
        }
        return generateRequest(signer, subjectPublicKeyInfo, subjectDn, attributes);
    }

    @Override
    public PKCS10CertificationRequest generateRequest(
            final ConcurrentContentSigner signer,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final X500Name subjectDn,
            final Map<ASN1ObjectIdentifier, ASN1Encodable> attributes)
    throws SecurityException {
        ParamUtil.requireNonNull("signer", signer);
        ParamUtil.requireNonNull("subjectPublicKeyInfo", subjectPublicKeyInfo);
        ParamUtil.requireNonNull("subjectDn", subjectDn);
        PKCS10CertificationRequestBuilder p10ReqBuilder =
                new PKCS10CertificationRequestBuilder(subjectDn, subjectPublicKeyInfo);
        if (CollectionUtil.isNonEmpty(attributes)) {
            for (ASN1ObjectIdentifier attrType : attributes.keySet()) {
                p10ReqBuilder.addAttribute(attrType, attributes.get(attrType));
            }
        }

        try {
            return signer.build(p10ReqBuilder);
        } catch (NoIdleSignerException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        }
    }

}
