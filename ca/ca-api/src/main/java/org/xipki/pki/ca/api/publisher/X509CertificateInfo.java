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

package org.xipki.pki.ca.api.publisher;

import java.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.RequestorInfo;
import org.xipki.pki.ca.api.X509Cert;
import org.xipki.pki.ca.api.X509CertWithDbId;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CertificateInfo {

    private final byte[] subjectPublicKey;

    private final X509CertWithDbId cert;

    private final X509Cert issuerCert;

    private final String profileName;

    private RequestType reqType;

    private byte[] transactionId;

    private RequestorInfo requestor;

    private String user;

    private String warningMessage;

    private CertRevocationInfo revocationInfo;

    private X500Name requestedSubject;

    private boolean alreadyIssued;

    public X509CertificateInfo(
            final X509CertWithDbId cert,
            final X509Cert issuerCert,
            final byte[] subjectPublicKey,
            final String profileName)
    throws CertificateEncodingException {
        ParamUtil.assertNotNull("cert", cert);
        ParamUtil.assertNotNull("issuerCert", issuerCert);
        ParamUtil.assertNotBlank("profileName", profileName);
        ParamUtil.assertNotNull("subjectPublicKey", subjectPublicKey);

        this.cert = cert;
        this.subjectPublicKey = subjectPublicKey;

        this.issuerCert = issuerCert;
        this.profileName = profileName;
    }

    public byte[] getSubjectPublicKey() {
        return subjectPublicKey;
    }

    public X509CertWithDbId getCert() {
        return cert;
    }

    public X509Cert getIssuerCert() {
        return issuerCert;
    }

    public String getProfileName() {
        return profileName;
    }

    public String getWarningMessage() {
        return warningMessage;
    }

    public void setWarningMessage(
            final String warningMessage) {
        this.warningMessage = warningMessage;
    }

    public RequestorInfo getRequestor() {
        return requestor;
    }

    public void setRequestor(
            final RequestorInfo requestor) {
        this.requestor = requestor;
    }

    public String getUser() {
        return user;
    }

    public void setUser(
            final String user) {
        this.user = user;
    }

    public boolean isRevoked() {
        return revocationInfo != null;
    }

    public CertRevocationInfo getRevocationInfo() {
        return revocationInfo;
    }

    public void setRevocationInfo(
            final CertRevocationInfo revocationInfo) {
        this.revocationInfo = revocationInfo;
    }

    public boolean isAlreadyIssued() {
        return alreadyIssued;
    }

    public void setAlreadyIssued(
            final boolean alreadyIssued) {
        this.alreadyIssued = alreadyIssued;
    }

    public RequestType getReqType() {
        return reqType;
    }

    public byte[] getTransactionId() {
        return transactionId;
    }

    public void setReqType(
            final RequestType reqType) {
        this.reqType = reqType;
    }

    public void setTransactionId(
            final byte[] transactionId) {
        this.transactionId = transactionId;
    }

    public X500Name getRequestedSubject() {
        return requestedSubject;
    }

    public void setRequestedSubject(
            final X500Name requestedSubject) {
        this.requestedSubject = requestedSubject;
    }

}
