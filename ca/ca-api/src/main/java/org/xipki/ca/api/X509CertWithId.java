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

package org.xipki.ca.api;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.Arrays;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;

/**
 * @author Lijun Liao
 */

public class X509CertWithId
{
    private Integer certId;
    private final X509Certificate cert;
    private final String subject;
    private final byte[] encodedCert;
    private final byte[] subjectKeyIdentifer;

    public X509CertWithId(X509Certificate cert)
    throws OperationException
    {
        this(cert, null);
    }

    public X509CertWithId(X509Certificate cert, byte[] encodedCert)
    throws OperationException
    {
        ParamChecker.assertNotNull("cert", cert);

        this.cert = cert;
        this.subject = SecurityUtil.getRFC4519Name(cert.getSubjectX500Principal());
        try
        {
            this.subjectKeyIdentifer = SecurityUtil.extractSKI(cert);
        } catch(CertificateEncodingException e)
        {
            throw new OperationException(ErrorCode.INVALID_EXTENSION, e.getMessage());
        }

        if(encodedCert == null)
        {
            try
            {
                this.encodedCert = cert.getEncoded();
            } catch (CertificateEncodingException e)
            {
                throw new OperationException(ErrorCode.System_Failure,
                        "CertificateEncodingException: " + e.getMessage());
            }
        }
        else
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

    @Override
    public String toString()
    {
        return cert.toString();
    }

    public Integer getCertId()
    {
        return certId;
    }

    public void setCertId(Integer certId)
    {
        this.certId = certId;
    }

    public byte[] getSubjectKeyIdentifier()
    {
        return Arrays.clone(subjectKeyIdentifer);
    }

}
