/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
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

package org.xipki.ca.api.profile;

import java.util.Date;
import java.util.TimeZone;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.common.BadCertTemplateException;
import org.xipki.ca.common.BadFormatException;
import org.xipki.ca.common.CertProfileException;
import org.xipki.security.common.EnvironmentParameterResolver;

/**
 * @author Lijun Liao
 */

public abstract class CertProfile
{
    private TimeZone timeZone = TimeZone.getDefault();

    public boolean isOnlyForRA()
    {
        return false;
    }

    public void shutdown()
    {
    }

    public SpecialCertProfileBehavior getSpecialCertProfileBehavior()
    {
        return null;
    }

    /**
     * Whether include subject and serial number of the issuer certificate in the
     * AuthorityKeyIdentifier extension.
     * @return
     */
    public boolean includeIssuerAndSerialInAKI()
    {
        return false;
    }

    public ExtensionOccurrence getOccurenceOfFreshestCRL()
    {
        return ExtensionOccurrence.NONCRITICAL_OPTIONAL;
    }

    public ExtensionOccurrence getOccurenceOfIssuerAltName()
    {
        return ExtensionOccurrence.NONCRITICAL_OPTIONAL;
    }

    public String incSerialNumber(String currentSerialNumber)
    throws BadFormatException
    {
        try
        {
            int currentSN = currentSerialNumber == null ? 0 : Integer.parseInt(currentSerialNumber.trim());
            return Integer.toString(currentSN + 1);
        }catch(NumberFormatException e)
        {
            throw new BadFormatException("invalid serialNumber attribute " + currentSerialNumber);
        }
    }

    public boolean isDuplicateKeyPermitted()
    {
        return true;
    }

    public boolean isDuplicateSubjectPermitted()
    {
        return true;
    }

    /**
     * Whether the subject attribute serialNumber in request is permitted
     */
    public boolean isSerialNumberInReqPermitted()
    {
        return true;
    }

    public String getParameter(String paramName)
    {
        return null;
    }

    public boolean hasMidnightNotBefore()
    {
        return false;
    }

    public TimeZone getTimezone()
    {
        return timeZone;
    }

    public abstract void initialize(String data)
    throws CertProfileException;

    public abstract void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver);

    public abstract Date getNotBefore(Date notBefore);

    public abstract Integer getValidity();

    public abstract void checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException;

    public abstract SubjectInfo getSubject(X500Name requestedSubject)
    throws CertProfileException, BadCertTemplateException;

    public abstract ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier();

    public abstract ExtensionOccurrence getOccurenceOfSubjectKeyIdentifier();

    public abstract ExtensionOccurrence getOccurenceOfCRLDistributinPoints();

    public abstract ExtensionOccurrence getOccurenceOfAuthorityInfoAccess();

    public abstract ExtensionTuples getExtensions(X500Name requestedSubject, Extensions requestedExtensions)
    throws CertProfileException, BadCertTemplateException;

    public abstract boolean incSerialNumberIfSubjectExists();

}
