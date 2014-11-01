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

package org.xipki.ocsp.api;

import java.util.Date;

import org.bouncycastle.asn1.ocsp.CrlID;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.HashAlgoType;

/**
 * @author Lijun Liao
 */

public class CertStatusInfo
{
    private final CertStatus certStatus;

    private CertRevocationInfo revocationInfo;
    private HashAlgoType certHashAlgo;
    private byte[] certHash;

    private final Date thisUpdate;
    private final Date nextUpdate;
    private final String certProfile;

    private CrlID crlID;
    private Date archiveCutOff;

    private CertStatusInfo(CertStatus certStatus, Date thisUpdate, Date nextUpdate, String certProfile)
    {
        this.certStatus = certStatus;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.certProfile = certProfile;
    }

    public static CertStatusInfo getUnknownCertStatusInfo(Date thisUpdate, Date nextUpdate)
    {
        return new CertStatusInfo(CertStatus.UNKNOWN, thisUpdate, nextUpdate, null);
    }

    public static CertStatusInfo getIssuerUnknownCertStatusInfo(Date thisUpdate, Date nextUpdate)
    {
        return new CertStatusInfo(CertStatus.ISSUER_UNKNOWN, thisUpdate, nextUpdate, null);
    }

    public static CertStatusInfo getGoodCertStatusInfo(
            HashAlgoType certHashAlgo, byte[] certHash,
            Date thisUpdate, Date nextUpdate, String certProfile)
    {
        CertStatusInfo ret = new CertStatusInfo(CertStatus.GOOD, thisUpdate, nextUpdate, certProfile);
        ret.certHashAlgo = certHashAlgo;
        ret.certHash = certHash;
        return ret;
    }

    public static CertStatusInfo getRevokedCertStatusInfo(CertRevocationInfo revocationInfo,
            HashAlgoType certHashAlgo, byte[] certHash,
            Date thisUpdate, Date nextUpdate, String certProfile)
    {
        if(revocationInfo == null)
        {
            throw new IllegalArgumentException("revocationInfo could not be null");
        }
        CertStatusInfo ret = new CertStatusInfo(CertStatus.REVOKED, thisUpdate, nextUpdate, certProfile);
        ret.revocationInfo = revocationInfo;
        ret.certHashAlgo = certHashAlgo;
        ret.certHash = certHash;
        return ret;
    }

    public Date getThisUpdate()
    {
        return thisUpdate;
    }

    public Date getNextUpdate()
    {
        return nextUpdate;
    }

    public CertStatus getCertStatus()
    {
        return certStatus;
    }

    public CertRevocationInfo getRevocationInfo()
    {
        return revocationInfo;
    }

    public HashAlgoType getCertHashAlgo()
    {
        return certHashAlgo;
    }

    public byte[] getCertHash()
    {
        return certHash;
    }

    public String getCertProfile()
    {
        return certProfile;
    }

    public CrlID getCrlID()
    {
        return crlID;
    }

    public void setCrlID(CrlID crlID)
    {
        this.crlID = crlID;
    }

    public Date getArchiveCutOff()
    {
        return archiveCutOff;
    }

    public void setArchiveCutOff(Date archiveCutOff)
    {
        this.archiveCutOff = archiveCutOff;
    }

}
