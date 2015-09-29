/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.pki.ca.api;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Arrays;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class X509Cert
{
    private final X509Certificate cert;
    private final String subject;
    private final byte[] encodedCert;
    private final byte[] subjectKeyIdentifer;
    private final X500Name subjectAsX500Name;

    public X509Cert(
            final X509Certificate cert)
    {
        this(cert, null);
    }

    public X509Cert(
            final X509Certificate cert,
            final byte[] encodedCert)
    {
        ParamUtil.assertNotNull("cert", cert);

        this.cert = cert;
        X500Principal x500Subject = cert.getSubjectX500Principal();
        this.subject = X509Util.getRFC4519Name(x500Subject);
        this.subjectAsX500Name = X500Name.getInstance(x500Subject.getEncoded());
        try
        {
            this.subjectKeyIdentifer = X509Util.extractSKI(cert);
        } catch (CertificateEncodingException e)
        {
            throw new RuntimeException("CertificateEncodingException: " + e.getMessage());
        }

        if (encodedCert == null)
        {
            try
            {
                this.encodedCert = cert.getEncoded();
            } catch (CertificateEncodingException e)
            {
                throw new RuntimeException("CertificateEncodingException: " + e.getMessage());
            }
        } else
        {
            this.encodedCert = encodedCert;
        }
    }

    public X509Certificate getCert()
    {
        return cert;
    }

    public byte[] getEncodedCert()
    {
        return encodedCert;
    }

    public String getSubject()
    {
        return subject;
    }

    public X500Name getSubjectAsX500Name()
    {
        return subjectAsX500Name;
    }

    @Override
    public String toString()
    {
        return cert.toString();
    }

    public byte[] getSubjectKeyIdentifier()
    {
        return Arrays.clone(subjectKeyIdentifer);
    }

}
