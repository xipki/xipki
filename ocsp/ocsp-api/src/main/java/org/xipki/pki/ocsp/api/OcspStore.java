/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class OcspStore {

    protected static final long DAY = 24L * 60 * 60 * 1000;

    protected String name;

    protected boolean unknownSerialAsGood;

    protected int retentionInterval;

    protected boolean includeArchiveCutoff;

    protected boolean includeCrlId;

    protected boolean ignoreExpiredCert;

    protected boolean ignoreNotYetValidCert;

    protected AuditServiceRegister auditServiceRegister;

    public OcspStore() {
    }

    public abstract Set<IssuerHashNameAndKey> issuerHashNameAndKeys();

    public abstract boolean canResolveIssuer(@NonNull HashAlgoType hashAlgo,
            @NonNull byte[] issuerNameHash, @NonNull byte[] issuerKeyHash);

    public abstract X509Certificate getIssuerCert(@NonNull HashAlgoType hashAlgo,
            @NonNull byte[] issuerNameHash, @NonNull byte[] issuerKeyHash);

    public abstract CertStatusInfo getCertStatus(@NonNull Date time, @NonNull HashAlgoType hashAlgo,
            @NonNull byte[] issuerNameHash, @NonNull byte[] issuerKeyHash,
            @NonNull BigInteger serialNumber, boolean includeCertHash,
            @Nullable HashAlgoType certHashAlg, @Nullable CertprofileOption certprofileOption)
            throws OcspStoreException;

    public abstract void init(@Nullable String conf, @Nullable DataSourceWrapper datasource,
            @NonNull Set<HashAlgoType> certHashAlgos) throws OcspStoreException;

    public abstract CertRevocationInfo getCaRevocationInfo(@NonNull HashAlgoType hashAlgo,
            @NonNull byte[] issuerNameHash, @NonNull byte[] issuerKeyHash);

    public abstract void shutdown() throws OcspStoreException;

    public abstract boolean isHealthy();

    public void setName(final String name) {
        this.name = ParamUtil.requireNonBlank("name", name);
    }

    public String name() {
        return name;
    }

    public void setAuditServiceRegister(final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = auditServiceRegister;
    }

    public AuditService auditService() {
        return auditServiceRegister.getAuditService();
    }

    public boolean isUnknownSerialAsGood() {
        return unknownSerialAsGood;
    }

    public void setUnknownSerialAsGood(final boolean unknownSerialAsGood) {
        this.unknownSerialAsGood = unknownSerialAsGood;
    }

    public boolean isIncludeArchiveCutoff() {
        return includeArchiveCutoff;
    }

    public void setIncludeArchiveCutoff(final boolean includeArchiveCutoff) {
        this.includeArchiveCutoff = includeArchiveCutoff;
    }

    public int retentionInterval() {
        return retentionInterval;
    }

    public void setRetentionInterval(final int retentionInterval) {
        this.retentionInterval = retentionInterval;
    }

    public boolean isIncludeCrlId() {
        return includeCrlId;
    }

    public void setIncludeCrlId(final boolean includeCrlId) {
        this.includeCrlId = includeCrlId;
    }

    public boolean isIgnoreExpiredCert() {
        return ignoreExpiredCert;
    }

    public void setIgnoreExpiredCert(boolean ignoreExpiredCert) {
        this.ignoreExpiredCert = ignoreExpiredCert;
    }

    public boolean isIgnoreNotYetValidCert() {
        return ignoreNotYetValidCert;
    }

    public void setIgnoreNotYetValidCert(boolean ignoreNotYetValidCert) {
        this.ignoreNotYetValidCert = ignoreNotYetValidCert;
    }

}
