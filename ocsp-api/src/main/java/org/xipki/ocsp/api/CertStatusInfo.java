/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

import java.util.Date;

import org.bouncycastle.asn1.ocsp.CrlID;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertStatusInfo {

    private final CertStatus certStatus;

    private CertRevocationInfo revocationInfo;

    private HashAlgoType certHashAlgo;

    private byte[] certHash;

    private final Date thisUpdate;

    private final Date nextUpdate;

    private final String certprofile;

    private CrlID crlId;

    private Date archiveCutOff;

    private CertStatusInfo(final CertStatus certStatus, final Date thisUpdate,
            final Date nextUpdate, final String certprofile) {
        this.certStatus = ParamUtil.requireNonNull("certStatus", certStatus);
        this.thisUpdate = ParamUtil.requireNonNull("thisUpdate", thisUpdate);
        this.nextUpdate = nextUpdate;
        this.certprofile = certprofile;
    }

    public Date thisUpdate() {
        return thisUpdate;
    }

    public Date nextUpdate() {
        return nextUpdate;
    }

    public CertStatus certStatus() {
        return certStatus;
    }

    public CertRevocationInfo revocationInfo() {
        return revocationInfo;
    }

    public HashAlgoType certHashAlgo() {
        return certHashAlgo;
    }

    public byte[] certHash() {
        return certHash;
    }

    public String certprofile() {
        return certprofile;
    }

    public CrlID crlId() {
        return crlId;
    }

    public void setCrlId(final CrlID crlId) {
        this.crlId = crlId;
    }

    public Date archiveCutOff() {
        return archiveCutOff;
    }

    public void setArchiveCutOff(final Date archiveCutOff) {
        this.archiveCutOff = archiveCutOff;
    }

    public static CertStatusInfo getUnknownCertStatusInfo(final Date thisUpdate,
            final Date nextUpdate) {
        return new CertStatusInfo(CertStatus.UNKNOWN, thisUpdate, nextUpdate, null);
    }

    public static CertStatusInfo getIgnoreCertStatusInfo(final Date thisUpdate,
            final Date nextUpdate) {
        return new CertStatusInfo(CertStatus.IGNORE, thisUpdate, nextUpdate, null);
    }

    public static CertStatusInfo getIssuerUnknownCertStatusInfo(final Date thisUpdate,
            final Date nextUpdate) {
        return new CertStatusInfo(CertStatus.ISSUER_UNKNOWN, thisUpdate, nextUpdate, null);
    }

    public static CertStatusInfo getGoodCertStatusInfo(final HashAlgoType certHashAlgo,
            final byte[] certHash, final Date thisUpdate, final Date nextUpdate,
            final String certprofile) {
        CertStatusInfo ret = new CertStatusInfo(CertStatus.GOOD, thisUpdate, nextUpdate,
                certprofile);
        ret.certHashAlgo = certHashAlgo;
        ret.certHash = certHash;
        return ret;
    }

    public static CertStatusInfo getRevokedCertStatusInfo(final CertRevocationInfo revocationInfo,
            final HashAlgoType certHashAlgo, final byte[] certHash, final Date thisUpdate,
            final Date nextUpdate, final String certprofile) {
        if (revocationInfo == null) {
            throw new IllegalArgumentException("revocationInfo must not be null");
        }
        CertStatusInfo ret = new CertStatusInfo(CertStatus.REVOKED, thisUpdate, nextUpdate,
                certprofile);
        ret.revocationInfo = revocationInfo;
        ret.certHashAlgo = certHashAlgo;
        ret.certHash = certHash;
        return ret;
    }

}
