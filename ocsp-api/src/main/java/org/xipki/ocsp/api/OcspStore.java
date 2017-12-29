/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ocsp.api;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
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

    /**
     *
     * @param reqIssuer
     *          Requested issuer
     * @return whether this OCSP store knows the given issuer.
     * FIXME: rename it to knowsIssuer.
     */
    public abstract boolean canResolveIssuer(RequestIssuer reqIssuer);

    /**
     *
     * @param reqIssuer
     *          Requested issuer
     * @return the certificate of the given issuer.
     */
    public abstract X509Certificate getIssuerCert(RequestIssuer reqIssuer);

    /**
     *
     * @param time
     *          Time of the certificate status. Must not be {@code null}.
     * @param reqIssuer
     *          Requested issuer
     * @param serialNumber
     *          Serial number of the target certificate. Must not be {@code null}.
     * @param includeCertHash
     *          Whether to include the hash of target certificate in the response.
     * @param includeRit
     *          Whether to include the revocation invalidity time in the response.
     * @param inheritCaRevocation
     *          Whether to inherit CA revocation
     * @param certHashAlg
     *          Hash algorithm of the certHash. If {@code null}, the algorithm specified
     *          in the parameter hashAlgo will be applied.
     * @return the certificate status.
     */
    public abstract CertStatusInfo getCertStatus(Date time, RequestIssuer reqIssuer,
            BigInteger serialNumber, boolean includeCertHash, boolean includeRit,
            boolean inheritCaRevocation, HashAlgoType certHashAlg)
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

    public abstract void shutdown() throws OcspStoreException;

    public abstract boolean isHealthy();

    public void setName(String name) {
        this.name = ParamUtil.requireNonBlank("name", name);
    }

    public String name() {
        return name;
    }

    public boolean isUnknownSerialAsGood() {
        return unknownSerialAsGood;
    }

    public void setUnknownSerialAsGood(boolean unknownSerialAsGood) {
        this.unknownSerialAsGood = unknownSerialAsGood;
    }

    public boolean isIncludeArchiveCutoff() {
        return includeArchiveCutoff;
    }

    public void setIncludeArchiveCutoff(boolean includeArchiveCutoff) {
        this.includeArchiveCutoff = includeArchiveCutoff;
    }

    public int retentionInterval() {
        return retentionInterval;
    }

    public void setRetentionInterval(int retentionInterval) {
        this.retentionInterval = retentionInterval;
    }

    public boolean isIncludeCrlId() {
        return includeCrlId;
    }

    public void setIncludeCrlId(boolean includeCrlId) {
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
