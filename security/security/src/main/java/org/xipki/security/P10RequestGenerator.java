/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class P10RequestGenerator
{

    public PKCS10CertificationRequest generateRequest(
            SecurityFactory securityFactory,
            String signerType, String signerConf,
            SubjectPublicKeyInfo subjectPublicKeyInfo,
            String subject)
    throws PasswordResolverException, SignerException
    {
        X500Name subjectDN = new X500Name(subject);
        return generateRequest(securityFactory, signerType, signerConf, subjectPublicKeyInfo, subjectDN);
    }

    public PKCS10CertificationRequest generateRequest(
            SecurityFactory securityFactory,
            String signerType, String signerConf,
            SubjectPublicKeyInfo subjectPublicKeyInfo,
            X500Name subjectDN)
    throws PasswordResolverException, SignerException
    {
        ConcurrentContentSigner signer = securityFactory.createSigner(signerType, signerConf,
                (X509Certificate[]) null);
        ContentSigner contentSigner;
        try
        {
            contentSigner = signer.borrowContentSigner();
        } catch (NoIdleSignerException e)
        {
            throw new SignerException(e.getMessage(), e);
        }
        try
        {
            return generateRequest(contentSigner, subjectPublicKeyInfo, subjectDN);
        }finally
        {
            signer.returnContentSigner(contentSigner);
        }
    }

    public PKCS10CertificationRequest generateRequest(
            ContentSigner contentSigner,
            SubjectPublicKeyInfo subjectPublicKeyInfo,
            X500Name subjectDN)
    {
        PKCS10CertificationRequestBuilder p10ReqBuilder =
                new PKCS10CertificationRequestBuilder(subjectDN, subjectPublicKeyInfo);

        return p10ReqBuilder.build(contentSigner);
    }

}
