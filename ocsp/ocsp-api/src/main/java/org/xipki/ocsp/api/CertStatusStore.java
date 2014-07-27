/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.api;

import java.math.BigInteger;
import java.util.Set;

import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public abstract class CertStatusStore
{
    public abstract CertStatusInfo getCertStatus(HashAlgoType hashAlgo, byte[] issuerNameHash,
            byte[] issuerKeyHash, BigInteger serialNumber, Set<String> excludeCertProfiles)
    throws CertStatusStoreException;

    public abstract void init(String conf, DataSourceFactory datasourceFactory, PasswordResolver passwordResolver)
    throws CertStatusStoreException;

    public abstract void shutdown()
    throws CertStatusStoreException;

    public abstract boolean isHealthy();

    protected static final long DAY = 24L * 60 * 60 * 1000;

    private final String name;
    protected boolean unknownSerialAsGood;
    protected int retentionInterval;
    protected boolean inheritCaRevocation;
    protected boolean includeArchiveCutoff;
    protected boolean includeCrlID;
    protected boolean includeCertHash;
    protected HashAlgoType certHashAlgorithm;

    protected AuditLoggingServiceRegister auditServiceRegister;

    protected CertStatusStore(String name)
    {
        ParamChecker.assertNotEmpty("name", name);
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public void setAuditServiceRegister(AuditLoggingServiceRegister auditServiceRegister)
    {
        this.auditServiceRegister = auditServiceRegister;
    }

    public AuditLoggingService getAuditLoggingService()
    {
        return auditServiceRegister == null ? null : auditServiceRegister.getAuditLoggingService();
    }

    public boolean isUnknownSerialAsGood()
    {
        return unknownSerialAsGood;
    }

    public void setUnknownSerialAsGood(boolean unknownSerialAsGood)
    {
        this.unknownSerialAsGood = unknownSerialAsGood;
    }

    public boolean isIncludeArchiveCutoff()
    {
        return includeArchiveCutoff;
    }

    public void setIncludeArchiveCutoff(boolean includeArchiveCutoff)
    {
        this.includeArchiveCutoff = includeArchiveCutoff;
    }

    public int getRetentionInterval()
    {
        return retentionInterval;
    }

    public void setRetentionInterval(int retentionInterval)
    {
        this.retentionInterval = retentionInterval;
    }

    public boolean isInheritCaRevocation()
    {
        return inheritCaRevocation;
    }

    public void setInheritCaRevocation(boolean inheritCaRevocation)
    {
        this.inheritCaRevocation = inheritCaRevocation;
    }

    public boolean isIncludeCrlID()
    {
        return includeCrlID;
    }

    public void setIncludeCrlID(boolean includeCrlID)
    {
        this.includeCrlID = includeCrlID;
    }

    public boolean isIncludeCertHash()
    {
        return includeCertHash;
    }

    public void setIncludeCertHash(boolean includeCertHash)
    {
        this.includeCertHash = includeCertHash;
    }

    public HashAlgoType getCertHashAlgorithm()
    {
        return certHashAlgorithm;
    }

    public void setCertHashAlgorithm(HashAlgoType algorithm)
    {
        this.certHashAlgorithm = algorithm;
    }

}
