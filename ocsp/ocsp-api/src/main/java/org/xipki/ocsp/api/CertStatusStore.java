/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ocsp.api;

import java.math.BigInteger;

import org.xipki.audit.api.AuditLoggingService;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.HashAlgoType;

public abstract class CertStatusStore
{
    public abstract CertStatusInfo getCertStatus(HashAlgoType hashAlgo, byte[] issuerNameHash,
            byte[] issuerKeyHash, BigInteger serialNumber)
    throws CertStatusStoreException;

    public abstract void init(String conf, DataSourceFactory datasourceFactory, PasswordResolver passwordResolver)
    throws CertStatusStoreException;

    public abstract void shutdown()
    throws CertStatusStoreException;

    public abstract boolean isHealthy();

    protected static final long DAY = 24L * 60 * 60 * 1000;

    private String name;
    protected boolean unknownSerialAsGood;
    protected int retentionInterval;
    protected boolean inheritCaRevocation;
    protected boolean includeArchiveCutoff;
    protected boolean includeCrlID;
    protected boolean includeCertHash;
    protected HashAlgoType certHashAlgorithm;

    protected AuditLoggingService auditLoggingService;

    protected CertStatusStore()
    {
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;
    }

    public AuditLoggingService getAuditLoggingService()
    {
        return auditLoggingService;
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
