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

package org.xipki.ca.api.publisher.x509;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.api.X509CertWithDbId;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgoType;
import org.xipki.security.X509Cert;
import org.xipki.security.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CertificateInfo {

    private final byte[] subjectPublicKey;

    private final X509CertWithDbId cert;

    private final NameId issuer;

    private final X509Cert issuerCert;

    private final NameId profile;

    private final NameId requestor;

    private final HashAlgoType hashAlgo;

    private RequestType reqType;

    private byte[] transactionId;

    private Integer user;

    private String warningMessage;

    private CertRevocationInfo revocationInfo;

    private X500Name requestedSubject;

    private boolean alreadyIssued;

    public X509CertificateInfo(final X509CertWithDbId cert, final NameId issuer,
            final X509Cert issuerCert, final byte[] subjectPublicKey, final NameId profile,
            final NameId requestor) throws CertificateEncodingException {
        this.profile = ParamUtil.requireNonNull("profile", profile);
        this.cert = ParamUtil.requireNonNull("cert", cert);
        this.subjectPublicKey = ParamUtil.requireNonNull("subjectPublicKey", subjectPublicKey);
        this.issuer = ParamUtil.requireNonNull("issuer", issuer);
        this.issuerCert = ParamUtil.requireNonNull("issuerCert", issuerCert);
        this.requestor = ParamUtil.requireNonNull("requestor", requestor);
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(cert.cert().getSigAlgOID());
        byte[] params = cert.cert().getSigAlgParams();

        try {
            AlgorithmIdentifier algId;
            algId = (params == null) ? new AlgorithmIdentifier(oid)
                    : new AlgorithmIdentifier(oid, new ASN1StreamParser(params).readObject());

            AlgorithmIdentifier hashId = AlgorithmUtil.extractDigesetAlgFromSigAlg(algId);
            this.hashAlgo = HashAlgoType.getNonNullHashAlgoType(hashId.getAlgorithm().getId());
        } catch (IllegalArgumentException | IOException | NoSuchAlgorithmException ex) {
            throw new CertificateEncodingException(
                    "could not retrieve hash algorithm used to sign the certificate: "
                            + ex.getMessage(), ex);
        }
    }

    public byte[] subjectPublicKey() {
        return subjectPublicKey;
    }

    public X509CertWithDbId cert() {
        return cert;
    }

    public NameId issuer() {
        return issuer;
    }

    public X509Cert issuerCert() {
        return issuerCert;
    }

    public NameId profile() {
        return profile;
    }

    public String warningMessage() {
        return warningMessage;
    }

    public void setWarningMessage(final String warningMessage) {
        this.warningMessage = warningMessage;
    }

    public NameId requestor() {
        return requestor;
    }

    public Integer user() {
        return user;
    }

    public void setUser(final Integer user) {
        this.user = user;
    }

    public boolean isRevoked() {
        return revocationInfo != null;
    }

    public CertRevocationInfo revocationInfo() {
        return revocationInfo;
    }

    public void setRevocationInfo(final CertRevocationInfo revocationInfo) {
        this.revocationInfo = revocationInfo;
    }

    public boolean isAlreadyIssued() {
        return alreadyIssued;
    }

    public void setAlreadyIssued(final boolean alreadyIssued) {
        this.alreadyIssued = alreadyIssued;
    }

    public RequestType reqType() {
        return reqType;
    }

    public byte[] transactionId() {
        return transactionId;
    }

    public void setReqType(final RequestType reqType) {
        this.reqType = reqType;
    }

    public void setTransactionId(final byte[] transactionId) {
        this.transactionId = transactionId;
    }

    public X500Name requestedSubject() {
        return requestedSubject;
    }

    public void setRequestedSubject(final X500Name requestedSubject) {
        this.requestedSubject = requestedSubject;
    }

    public HashAlgoType hashAlgo() {
        return hashAlgo;
    }

}
