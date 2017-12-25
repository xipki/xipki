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

package org.xipki.ca.server.mgmt.api.x509;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.common.util.Base64;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgoType;
import org.xipki.security.KeyUsage;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CaEntry extends CaEntry {

    private List<String> crlUris;

    private List<String> deltaCrlUris;

    private List<String> ocspUris;

    private List<String> cacertUris;

    private X509Certificate cert;

    private String crlSignerName;

    private int serialNoBitLen;

    private long nextCrlNumber;

    private int numCrls;

    private CertRevocationInfo revocationInfo;

    private String subject;

    private String hexSha1OfCert;

    public X509CaEntry(final NameId nameId, final int serialNoBitLen,
            final long nextCrlNumber, final String signerType, final String signerConf,
            final X509CaUris caUris, final int numCrls, final int expirationPeriod)
            throws CaMgmtException {
        super(nameId, signerType, signerConf, expirationPeriod);
        init(serialNoBitLen, nextCrlNumber, caUris, numCrls);
    }

    private void init(final int serialNoBitLen, final long nextCrlNumber, final X509CaUris caUris,
            final int numCrls) throws CaMgmtException {
        this.numCrls = ParamUtil.requireMin("numCrls", numCrls, 1);
        this.serialNoBitLen = ParamUtil.requireRange("serialNoBitLen", serialNoBitLen, 63, 159);
        this.nextCrlNumber = ParamUtil.requireMin("nextCrlNumber", nextCrlNumber, 1);

        this.cacertUris = caUris.cacertUris();
        this.ocspUris = caUris.ocspUris();
        this.crlUris = caUris.crlUris();
        this.deltaCrlUris = caUris.deltaCrlUris();
    }

    public void setCertificate(final X509Certificate certificate) throws CaMgmtException {
        if (certificate == null) {
            this.cert = null;
            this.subject = null;
            this.hexSha1OfCert = null;
        } else {
            if (!X509Util.hasKeyusage(certificate, KeyUsage.keyCertSign)) {
                throw new CaMgmtException("CA certificate does not have keyusage keyCertSign");
            }
            this.cert = certificate;
            this.subject = X509Util.getRfc4519Name(certificate.getSubjectX500Principal());
            byte[] encodedCert;
            try {
                encodedCert = certificate.getEncoded();
            } catch (CertificateEncodingException ex) {
                throw new CaMgmtException("could not encoded certificate", ex);
            }
            this.hexSha1OfCert = HashAlgoType.SHA1.hexHash(encodedCert);
        }
    }

    public int serialNoBitLen() {
        return serialNoBitLen;
    }

    public void setSerialNoBitLen(final int serialNoBitLen) {
        this.serialNoBitLen = ParamUtil.requireMin("serialNoBitLen", serialNoBitLen, 63);
    }

    public long nextCrlNumber() {
        return nextCrlNumber;
    }

    public void setNextCrlNumber(final long crlNumber) {
        this.nextCrlNumber = crlNumber;
    }

    public List<String> crlUris() {
        return crlUris;
    }

    public String crlUrisAsString() {
        return toString(crlUris);
    }

    public List<String> deltaCrlUris() {
        return deltaCrlUris;
    }

    public String deltaCrlUrisAsString() {
        return toString(deltaCrlUris);
    }

    public List<String> ocspUris() {
        return ocspUris;
    }

    public String ocspUrisAsString() {
        return toString(ocspUris);
    }

    public List<String> cacertUris() {
        return cacertUris;
    }

    public String cacertUrisAsString() {
        return toString(cacertUris);
    }

    public X509Certificate certificate() {
        return cert;
    }

    public int numCrls() {
        return numCrls;
    }

    public String crlSignerName() {
        return crlSignerName;
    }

    public void setCrlSignerName(final String crlSignerName) {
        this.crlSignerName = (crlSignerName == null) ? null : crlSignerName.toUpperCase();
    }

    public String toString(final boolean verbose, final boolean ignoreSensitiveInfo) {
        StringBuilder sb = new StringBuilder(1000);
        sb.append(super.toString(verbose, ignoreSensitiveInfo));
        if (sb.charAt(sb.length() - 1) != '\n') {
            sb.append('\n');
        }
        sb.append("serialNoBitLen: ").append(serialNoBitLen).append('\n');
        sb.append("nextCrlNumber: ").append(nextCrlNumber).append('\n');
        sb.append("deltaCrlUris: ").append(deltaCrlUrisAsString()).append('\n');
        sb.append("crlUris: ").append(crlUrisAsString()).append('\n');
        sb.append("ocspUris: ").append(ocspUrisAsString()).append('\n');
        sb.append("caCertUris: ").append(cacertUrisAsString()).append('\n');
        sb.append("cert: ").append("\n");
        if (cert == null) {
            sb.append("\tnull").append("\n");
        } else {
            sb.append("\tissuer: ").append(
                    X509Util.getRfc4519Name(cert.getIssuerX500Principal())).append("\n");
            sb.append("\tserialNumber: ").append(LogUtil.formatCsn(cert.getSerialNumber()))
                    .append("\n");
            sb.append("\tsubject: ").append(subject).append("\n");
            sb.append("\tnotBefore: ").append(cert.getNotBefore()).append("\n");
            sb.append("\tnotAfter: ").append(cert.getNotAfter()).append("\n");
            if (verbose) {
                String b64EncodedCert = null;
                try {
                    b64EncodedCert = Base64.encodeToString(cert.getEncoded());
                } catch (CertificateEncodingException ex) {
                    b64EncodedCert = "ERROR, could not encode the certificate";
                }
                sb.append("\tencoded: ").append(b64EncodedCert).append("\n");
            }
        }

        sb.append("crlSignerName: ").append(crlSignerName).append('\n');
        sb.append("revocation: ");
        sb.append(revocationInfo == null ? "not revoked" : "revoked");
        sb.append("\n");
        if (revocationInfo != null) {
            sb.append("\treason: ").append(revocationInfo.reason().description())
                .append("\n");
            sb.append("\trevoked at ").append(revocationInfo.revocationTime()).append("\n");
        }

        return sb.toString();
    } // method toString

    public CertRevocationInfo revocationInfo() {
        return revocationInfo;
    }

    public void setRevocationInfo(final CertRevocationInfo revocationInfo) {
        this.revocationInfo = revocationInfo;
    }

    public Date crlBaseTime() {
        return (cert == null) ? null : cert.getNotBefore();
    }

    public String subject() {
        return subject;
    }

    public String hexSha1OfCert() {
        return hexSha1OfCert;
    }

    @Override
    public void setExtraControl(final String extraControl) {
        super.setExtraControl(extraControl);
    }

    @Override
    public boolean equals(Object obj) {
        return equals(obj, false);
    }

    public boolean equals(Object obj, boolean ignoreDynamicFields) {
        if (! (obj instanceof X509CaEntry)) {
            return false;
        }

        if (!super.equals(obj)) {
            return false;
        }

        X509CaEntry objB = (X509CaEntry) obj;

        if (!ignoreDynamicFields) {
            if (nextCrlNumber != objB.nextCrlNumber) {
                return false;
            }
        }

        if (!CompareUtil.equalsObject(crlUris, objB.crlUris)) {
            return false;
        }

        if (!CompareUtil.equalsObject(deltaCrlUris, objB.deltaCrlUris)) {
            return false;
        }

        if (!CompareUtil.equalsObject(ocspUris, objB.ocspUris)) {
            return false;
        }

        if (!CompareUtil.equalsObject(cacertUris, objB.cacertUris)) {
            return false;
        }

        if (!CompareUtil.equalsObject(cert, objB.cert)) {
            return false;
        }

        if (!CompareUtil.equalsObject(crlSignerName, objB.crlSignerName)) {
            return false;
        }

        if (serialNoBitLen != objB.serialNoBitLen) {
            return false;
        }

        if (numCrls != objB.numCrls) {
            return false;
        }

        if (!CompareUtil.equalsObject(revocationInfo, objB.revocationInfo)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return ident().hashCode();
    }

}
