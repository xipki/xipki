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

package org.xipki.ca.api.publisher;

import java.security.cert.CertificateEncodingException;

import org.xipki.ca.api.RequestorInfo;
import org.xipki.ca.api.X509CertWithId;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class X509CertificateInfo
{
    private final byte[] subjectPublicKey;
    private final X509CertWithId cert;
    private final X509CertWithId issuerCert;
    private final String profileName;

    private RequestorInfo requestor;
    private String user;

    private String warningMessage;

    private CertRevocationInfo revInfo;
    private boolean alreadyIssued;

    public X509CertificateInfo(X509CertWithId cert,
            X509CertWithId issuerCert,
            byte[] subjectPublicKey,
            String profileName)
    throws CertificateEncodingException
    {
        ParamChecker.assertNotNull("cert", cert);
        ParamChecker.assertNotNull("issuerCert", issuerCert);
        ParamChecker.assertNotEmpty("profileName", profileName);
        ParamChecker.assertNotNull("subjectPublicKey", subjectPublicKey);

        this.cert = cert;
        this.subjectPublicKey = subjectPublicKey;

        this.issuerCert = issuerCert;
        this.profileName = profileName;
    }

    public byte[] getSubjectPublicKey()
    {
        return subjectPublicKey;
    }

    public X509CertWithId getCert()
    {
        return cert;
    }

    public X509CertWithId getIssuerCert()
    {
        return issuerCert;
    }

    public String getProfileName()
    {
        return profileName;
    }

    public String getWarningMessage()
    {
        return warningMessage;
    }

    public void setWarningMessage(String warningMessage)
    {
        this.warningMessage = warningMessage;
    }

    public RequestorInfo getRequestor()
    {
        return requestor;
    }

    public void setRequestor(RequestorInfo requestor)
    {
        this.requestor = requestor;
    }

    public String getUser()
    {
        return user;
    }

    public void setUser(String user)
    {
        this.user = user;
    }

    public boolean isRevoked()
    {
        return revInfo != null;
    }

    public CertRevocationInfo getRevocationInfo()
    {
        return revInfo;
    }

    public void setRevocationInfo(CertRevocationInfo revInfo)
    {
        this.revInfo = revInfo;
    }

    public boolean isAlreadyIssued()
    {
        return alreadyIssued;
    }

    public void setAlreadyIssued(boolean alreadyIssued)
    {
        this.alreadyIssued = alreadyIssued;
    }

}
