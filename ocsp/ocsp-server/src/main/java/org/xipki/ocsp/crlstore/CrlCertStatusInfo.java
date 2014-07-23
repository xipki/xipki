/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.crlstore;

import java.util.Date;
import java.util.Map;

import org.xipki.ocsp.api.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.ParamChecker;

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
