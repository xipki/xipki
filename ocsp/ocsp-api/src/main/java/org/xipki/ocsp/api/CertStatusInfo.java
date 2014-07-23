/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.api;

import java.util.Date;

import org.bouncycastle.asn1.ocsp.CrlID;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.HashAlgoType;

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
