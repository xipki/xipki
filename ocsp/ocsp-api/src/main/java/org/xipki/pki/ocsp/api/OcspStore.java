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

    public OcspStore() {
    }

    public abstract Set<IssuerHashNameAndKey> issuerHashNameAndKeys();

    /**
     *
     * @param hashAlgo
     *          Hash algorithm. Must not be {@code null}.
     * @param issuerNameHash
     *          Hash of the issuer's subject. Must not be {@code null}.
     * @param issuerKeyHash
     *          Hash of the issuer's public key. Must not be {@code null}.
     * @return whether this OCSP store knows the given issuer.
     * FIXME: rename it to knowsIssuer.
     */
    public abstract boolean canResolveIssuer(HashAlgoType hashAlgo,
            byte[] issuerNameHash, byte[] issuerKeyHash);

    /**
     *
     * @param hashAlgo
     *          Hash algorithm. Must not be {@code null}.
     * @param issuerNameHash
     *          Hash of the issuer's subject. Must not be {@code null}.
     * @param issuerKeyHash
     *          Hash of the issuer's public key. Must not be {@code null}.
     * @return the certificate of the given issuer.
     */
    public abstract X509Certificate getIssuerCert(HashAlgoType hashAlgo,
            byte[] issuerNameHash, byte[] issuerKeyHash);

    /**
     *
     * @param time
     *          Time of the certificate status. Must not be {@code null}.
     * @param hashAlgo
     *          Hash algorithm to compute issuerNameHash and issuerKeyHash.
     *          Must not be {@code null}.
     * @param issuerNameHash
     *          Hash of the issuer's subject. Must not be {@code null}.
     * @param issuerKeyHash
     *          Hash of the issuer's public key. Must not be {@code null}.
     * @param serialNumber
     *          Serial number of the target certificate. Must not be {@code null}.
     * @param includeCertHash
     *          Whether to include the hash of target certificate in the response.
     * @param includeRit
     *          Whether to include the revocation invalidity time in the response.
     * @param certHashAlg
     *          Hash algorithm of the certHash. If {@code null}, the algorithm specified
     *          in the parameter hashAlgo will be applied.
     * @return the certificate status.
     */
    public abstract CertStatusInfo getCertStatus(Date time, HashAlgoType hashAlgo,
            byte[] issuerNameHash, byte[] issuerKeyHash, BigInteger serialNumber,
            boolean includeCertHash, boolean includeRit, HashAlgoType certHashAlg)
            throws OcspStoreException;

    /**
     *
     * @param conf
     *          Configuration. Could be {@code null}.
     * @param datasource
     *          Datasource. Could be {@code null}.
     */
    public abstract void init(String conf, DataSourceWrapper datasource)
            throws OcspStoreException;

    /**
     *
     * @param hashAlgo
     *          Hash algorithm to compute issuerNameHash and issuerKeyHash.
     *          Must not be {@code null}.
     * @param issuerNameHash
     *          Hash of the issuer's subject. Must not be {@code null}.
     * @param issuerKeyHash
     *          Hash of the issuer's public key. Must not be {@code null}.
     * @return the revocation information of the queried certificate.
     */
    public abstract CertRevocationInfo getCaRevocationInfo(HashAlgoType hashAlgo,
            byte[] issuerNameHash, byte[] issuerKeyHash);

    public abstract void shutdown() throws OcspStoreException;

    public abstract boolean isHealthy();

    public void setName(final String name) {
        this.name = ParamUtil.requireNonBlank("name", name);
    }

    public String name() {
        return name;
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
