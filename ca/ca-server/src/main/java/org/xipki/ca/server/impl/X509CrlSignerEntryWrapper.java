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

package org.xipki.ca.server.impl;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.server.mgmt.api.X509CrlSignerEntry;
import org.xipki.common.ConfigurationException;
import org.xipki.common.KeyUsage;
import org.xipki.common.util.X509Util;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

class X509CrlSignerEntryWrapper
{
    private X509CrlSignerEntry dbEntry;
    private CRLControl crlControl;
    private ConcurrentContentSigner signer;
    private byte[] subjectKeyIdentifier;

    public X509CrlSignerEntryWrapper()
    {
    }

    public void setDbEntry(
            final X509CrlSignerEntry dbEntry)
    throws ConfigurationException
    {
        this.dbEntry = dbEntry;
        this.crlControl = new CRLControl(dbEntry.getCRLControl());
    }

    public CRLControl getCRLControl()
    {
        return crlControl;
    }

    public void initSigner(
            final SecurityFactory securityFactory)
    throws SignerException, OperationException, ConfigurationException
    {
        if(signer != null)
        {
            return;
        }

        if(dbEntry == null)
        {
            throw new SignerException("dbEntry is null");
        }

        if("CA".equals(dbEntry.getType()))
        {
            return;
        }

        X509Certificate responderCert = dbEntry.getCertificate();
        signer = securityFactory.createSigner(
                dbEntry.getType(), dbEntry.getConf(), responderCert);
        if(dbEntry.getBase64Cert() == null)
        {
            dbEntry.setCertificate(signer.getCertificate());
        }

        byte[] encodedSkiValue = signer.getCertificate().getExtensionValue(
                Extension.subjectKeyIdentifier.getId());
        if(encodedSkiValue == null)
        {
            throw new OperationException(ErrorCode.INVALID_EXTENSION,
                    "CA certificate does not have required extension SubjectKeyIdentifier");
        }

        ASN1OctetString ski;
        try
        {
            ski = (ASN1OctetString) X509ExtensionUtil.fromExtensionValue(encodedSkiValue);
        } catch (IOException e)
        {
            throw new OperationException(ErrorCode.INVALID_EXTENSION, e.getMessage());
        }
        this.subjectKeyIdentifier = ski.getOctets();

        if(X509Util.hasKeyusage(signer.getCertificate(), KeyUsage.cRLSign) == false)
        {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "CRL signer does not have keyusage cRLSign");
        }
    }

    public X509CrlSignerEntry getDbEntry()
    {
        return dbEntry;
    }

    public X509Certificate getCert()
    {
        if(signer == null)
        {
            return dbEntry.getCertificate();
        } else
        {
            return signer.getCertificate();
        }
    }

    public byte[] getSubjectKeyIdentifier()
    {
        return subjectKeyIdentifier == null ? null : Arrays.clone(subjectKeyIdentifier);
    }

    public ConcurrentContentSigner getSigner()
    {
        return signer;
    }

}
