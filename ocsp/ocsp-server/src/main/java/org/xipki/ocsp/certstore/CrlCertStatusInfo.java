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

package org.xipki.ocsp.certstore;

import java.util.Date;
import java.util.Map;

import org.xipki.common.CertRevocationInfo;
import org.xipki.common.HashAlgoType;
import org.xipki.common.ParamChecker;
import org.xipki.ocsp.api.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo;

/**
 * @author Lijun Liao
 */

class CrlCertStatusInfo
{
    private final CertStatus certStatus;
    private final CertRevocationInfo revocationInfo;
    private final String certProfile;
    private final Map<HashAlgoType, byte[]> certHashes;

    private CrlCertStatusInfo(CertStatus certStatus, CertRevocationInfo revocationInfo,
            String certProfile,
            Map<HashAlgoType, byte[]> certHashes)
    {
        this.certStatus = certStatus;
        this.revocationInfo = revocationInfo;
        this.certProfile = certProfile;
        this.certHashes = certHashes;
    }

    static CrlCertStatusInfo getUnknownCertStatusInfo(Date thisUpdate)
    {
        return new CrlCertStatusInfo(CertStatus.UNKNOWN, null, null, null);
    }

    static CrlCertStatusInfo getGoodCertStatusInfo(
            String certProfile,
            Map<HashAlgoType, byte[]> certHashes)
    {
        ParamChecker.assertNotEmpty("certProfile", certProfile);
        return new CrlCertStatusInfo(CertStatus.GOOD, null, certProfile, certHashes);
    }

    static CrlCertStatusInfo getRevokedCertStatusInfo(
            CertRevocationInfo revocationInfo,
            String certProfile,
            Map<HashAlgoType, byte[]> certHashes)
    {
        ParamChecker.assertNotNull("revocationInfo", revocationInfo);
        return new CrlCertStatusInfo(CertStatus.REVOKED, revocationInfo, certProfile, certHashes);
    }

    CertStatus getCertStatus()
    {
        return certStatus;
    }

    CertRevocationInfo getRevocationInfo()
    {
        return revocationInfo;
    }

    String getCertProfile()
    {
        return certProfile;
    }

    byte[] getCertHash(HashAlgoType hashAlgo)
    {
        return certHashes == null ? null : certHashes.get(hashAlgo);
    }

    CertStatusInfo getCertStatusInfo(HashAlgoType hashAlgo, Date thisUpdate, Date nextUpdate)
    {
        switch(certStatus)
        {
        case ISSUER_UNKNOWN:
        case UNKNOWN:
            return CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, nextUpdate);
        case GOOD:
        case REVOKED:
            byte[] certHash = null;
            if(hashAlgo != null)
            {
                certHash = getCertHash(hashAlgo);
            }
            if(certStatus == CertStatus.GOOD)
            {
                return CertStatusInfo.getGoodCertStatusInfo(hashAlgo, certHash, thisUpdate, nextUpdate, certProfile);
            }
            else
            {
                return CertStatusInfo.getRevokedCertStatusInfo(revocationInfo, hashAlgo,
                        certHash, thisUpdate, nextUpdate, certProfile);
            }
        }

        return null;
    }

}
