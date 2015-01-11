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

package org.xipki.ca.server;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.server.mgmt.CRLControl;
import org.xipki.common.ConfigurationException;
import org.xipki.common.KeyUsage;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;
import org.xipki.security.api.ConcurrentContentSigner;

/**
 * @author Lijun Liao
 */

public class CrlSigner
{
    private final ConcurrentContentSigner signer;
    private final byte[] subjectKeyIdentifier;

    private final CRLControl crlControl;

    public CrlSigner(ConcurrentContentSigner signer, String crlControlConf)
    throws OperationException, ConfigurationException
    {
        this(signer, CRLControl.getInstance(crlControlConf));
    }

    public CrlSigner(ConcurrentContentSigner signer, CRLControl crlControl)
    throws OperationException
    {
        ParamChecker.assertNotNull("crlControl", crlControl);

        this.signer = signer;
        this.crlControl = crlControl;

        if(signer == null)
        {
            subjectKeyIdentifier = null;
        }
        else
        {
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

            if(SecurityUtil.hasKeyusage(signer.getCertificate(), KeyUsage.cRLSign) == false)
            {
                throw new OperationException(ErrorCode.System_Failure,
                        "CRL signer does not have keyusage cRLSign");
            }
        }
    }

    public ConcurrentContentSigner getSigner()
    {
        return signer;
    }

    public CRLControl getCRLcontrol()
    {
        return crlControl;
    }

    public byte[] getSubjectKeyIdentifier()
    {
        return subjectKeyIdentifier == null ? null : Arrays.clone(subjectKeyIdentifier);
    }

}
