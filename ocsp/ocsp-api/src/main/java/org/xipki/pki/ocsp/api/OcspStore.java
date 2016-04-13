/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.pki.ocsp.api;

import java.math.BigInteger;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.xipki.commons.audit.api.AuditService;
import org.xipki.commons.audit.api.AuditServiceRegister;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class OcspStore {

    protected static final long DAY = 24L * 60 * 60 * 1000;

    private String name;

    private boolean unknownSerialAsGood;

    private int retentionInterval;

    private boolean includeArchiveCutoff;

    private boolean includeCrlId;

    private AuditServiceRegister auditServiceRegister;

    public OcspStore() {
    }

    public abstract Set<IssuerHashNameAndKey> getIssuerHashNameAndKeys();

    public abstract boolean canResolveIssuer(
            @Nonnull HashAlgoType hashAlgo,
            @Nonnull byte[] issuerNameHash,
            @Nonnull byte[] issuerKeyHash);

    public abstract CertStatusInfo getCertStatus(
            @Nonnull HashAlgoType hashAlgo,
            @Nonnull byte[] issuerNameHash,
            @Nonnull byte[] issuerKeyHash,
            @Nonnull BigInteger serialNumber,
            boolean includeCertHash,
            @Nullable HashAlgoType certHashAlg,
            @Nullable CertprofileOption certprofileOption)
    throws OcspStoreException;

    public abstract void init(
            @Nonnull String conf,
            @Nonnull DataSourceWrapper datasource,
            @Nonnull Set<HashAlgoType> certHashAlgos)
    throws OcspStoreException;

    public abstract CertRevocationInfo getCaRevocationInfo(
            @Nonnull HashAlgoType hashAlgo,
            @Nonnull byte[] issuerNameHash,
            @Nonnull byte[] issuerKeyHash);

    public abstract void shutdown()
    throws OcspStoreException;

    public abstract boolean isHealthy();

    public void setName(
            final String name) {
        this.name = ParamUtil.requireNonBlank("name", name);
    }

    public String getName() {
        return name;
    }

    public void setAuditServiceRegister(
            final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = auditServiceRegister;
    }

    public AuditService getAuditService() {
        return (auditServiceRegister == null)
                ? null
                : auditServiceRegister.getAuditService();
    }

    public boolean isUnknownSerialAsGood() {
        return unknownSerialAsGood;
    }

    public void setUnknownSerialAsGood(
            final boolean unknownSerialAsGood) {
        this.unknownSerialAsGood = unknownSerialAsGood;
    }

    public boolean isIncludeArchiveCutoff() {
        return includeArchiveCutoff;
    }

    public void setIncludeArchiveCutoff(
            final boolean includeArchiveCutoff) {
        this.includeArchiveCutoff = includeArchiveCutoff;
    }

    public int getRetentionInterval() {
        return retentionInterval;
    }

    public void setRetentionInterval(
            final int retentionInterval) {
        this.retentionInterval = retentionInterval;
    }

    public boolean isIncludeCrlId() {
        return includeCrlId;
    }

    public void setIncludeCrlId(
            final boolean includeCrlId) {
        this.includeCrlId = includeCrlId;
    }

}
