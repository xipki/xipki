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

package org.xipki.pki.ca.server.mgmt.api.x509;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.commons.common.util.CompareUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.CertRevocationInfo;
import org.xipki.commons.security.HashAlgoType;
import org.xipki.commons.security.KeyUsage;
import org.xipki.commons.security.util.X509Util;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;

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

        this.cacertUris = caUris.getCacertUris();
        this.ocspUris = caUris.getOcspUris();
        this.crlUris = caUris.getCrlUris();
        this.deltaCrlUris = caUris.getDeltaCrlUris();
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

    public int getSerialNoBitLen() {
        return serialNoBitLen;
    }

    public void setSerialNoBitLen(final int serialNoBitLen) {
        this.serialNoBitLen = ParamUtil.requireMin("serialNoBitLen", serialNoBitLen, 63);
    }

    public long getNextCrlNumber() {
        return nextCrlNumber;
    }

    public void setNextCrlNumber(final long crlNumber) {
        this.nextCrlNumber = crlNumber;
    }

    public List<String> getCrlUris() {
        return crlUris;
    }

    public String getCrlUrisAsString() {
        return toString(crlUris);
    }

    public List<String> getDeltaCrlUris() {
        return deltaCrlUris;
    }

    public String getDeltaCrlUrisAsString() {
        return toString(deltaCrlUris);
    }

    public List<String> getOcspUris() {
        return ocspUris;
    }

    public String getOcspUrisAsString() {
        return toString(ocspUris);
    }

    public List<String> getCacertUris() {
        return cacertUris;
    }

    public String getCacertUrisAsString() {
        return toString(cacertUris);
    }

    public X509Certificate getCertificate() {
        return cert;
    }

    public int getNumCrls() {
        return numCrls;
    }

    public String getCrlSignerName() {
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
        sb.append("deltaCrlUris: ").append(getDeltaCrlUrisAsString()).append('\n');
        sb.append("crlUris: ").append(getCrlUrisAsString()).append('\n');
        sb.append("ocspUris: ").append(getOcspUrisAsString()).append('\n');
        sb.append("caCertUris: ").append(getCacertUrisAsString()).append('\n');
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
                    b64EncodedCert = Base64.toBase64String(cert.getEncoded());
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
            sb.append("\treason: ").append(revocationInfo.getReason().getDescription())
                .append("\n");
            sb.append("\trevoked at ").append(revocationInfo.getRevocationTime()).append("\n");
        }

        return sb.toString();
    } // method toString

    public CertRevocationInfo getRevocationInfo() {
        return revocationInfo;
    }

    public void setRevocationInfo(final CertRevocationInfo revocationInfo) {
        this.revocationInfo = revocationInfo;
    }

    public Date getCrlBaseTime() {
        return (cert == null) ? null : cert.getNotBefore();
    }

    public String getSubject() {
        return subject;
    }

    public String getHexSha1OfCert() {
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
        return getIdent().hashCode();
    }

}
