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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.scep.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.scep.client.exception.OperationNotSupportedException;
import org.xipki.scep.client.exception.ScepClientException;
import org.xipki.scep.crypto.HashAlgoType;
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.exception.MessageEncodingException;
import org.xipki.scep.message.AuthorityCertStore;
import org.xipki.scep.message.CACaps;
import org.xipki.scep.message.DecodedNextCAMessage;
import org.xipki.scep.message.DecodedPkiMessage;
import org.xipki.scep.message.IssuerAndSubject;
import org.xipki.scep.message.PkiMessage;
import org.xipki.scep.transaction.CACapability;
import org.xipki.scep.transaction.MessageType;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.transaction.TransactionId;
import org.xipki.scep.util.ParamUtil;
import org.xipki.scep.util.ScepConstants;
import org.xipki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public abstract class Client {

    public static final String REQ_CONTENT_TYPE = "application/octet-stream";

    // 5 minutes
    public static final long DEFAULT_SIGNINGTIME_BIAS = 5L * 60 * 1000;

    protected final CAIdentifier cAId;

    protected CACaps cACaps;

    private final CACertValidator cACertValidator;

    private long maxSigningTimeBiasInMs = DEFAULT_SIGNINGTIME_BIAS;

    private AuthorityCertStore authorityCertStore;

    private CollectionStore<X509CertificateHolder> responseSignerCerts;

    private boolean httpGetOnly = false;

    private boolean useInsecureAlgorithms = false;

    public Client(
            final CAIdentifier cAId,
            final CACertValidator cACertValidator)
    throws MalformedURLException {
        ParamUtil.assertNotNull("cAId", cAId);
        ParamUtil.assertNotNull("cACertValidator", cACertValidator);

        this.cAId = cAId;
        this.cACertValidator = cACertValidator;
    }

    protected abstract ScepHttpResponse httpPOST(
            final String url,
            final String requestContentType,
            final byte[] request)
    throws ScepClientException;

    protected abstract ScepHttpResponse httpGET(
            final String url)
    throws ScepClientException;

    public boolean isHttpGetOnly() {
        return httpGetOnly;
    }

    public void setHttpGetOnly(
            final boolean httpGetOnly) {
        this.httpGetOnly = httpGetOnly;
    }

    public boolean isUseInsecureAlgorithms() {
        return useInsecureAlgorithms;
    }

    public void setUseInsecureAlgorithms(
            final boolean useInsecureAlgorithms) {
        this.useInsecureAlgorithms = useInsecureAlgorithms;
    }

    public long getMaxSigningTimeBiasInMs() {
        return maxSigningTimeBiasInMs;
    }

    /**
     *
     * @param maxSigningTimeBiasInMs zero or negative value deactivates the message time check
     */
    public void setMaxSigningTimeBiasInMs(
            final long maxSigningTimeBiasInMs) {
        this.maxSigningTimeBiasInMs = maxSigningTimeBiasInMs;
    }

    private ScepHttpResponse httpSend(
            final Operation operation,
            final ContentInfo pkiMessage)
    throws ScepClientException {
        byte[] request = null;
        if (pkiMessage != null) {
            try {
                request = pkiMessage.getEncoded();
            } catch (IOException e) {
                throw new ScepClientException(e);
            }
        }

        if (Operation.GetCACaps == operation || Operation.GetCACert == operation
                || Operation.GetNextCACert == operation) {
            String url = cAId.buildGetUrl(operation, cAId.getProfile());
            return httpGET(url);
        } else {
            if (!httpGetOnly && cACaps.containsCapability(CACapability.POSTPKIOperation)) {
                String url = cAId.buildPostUrl(operation);
                return httpPOST(url, REQ_CONTENT_TYPE, request);
            } else {
                String url = cAId.buildGetUrl(operation,
                        (request == null)
                            ? null
                            : Base64.toBase64String(request));
                return httpGET(url);
            }
        } // end if
    }

    private ScepHttpResponse httpSend(
            final Operation operation)
    throws ScepClientException {
        return httpSend(operation, null);
    }

    public void init()
    throws ScepClientException {
        refresh();
    }

    public void refresh()
    throws ScepClientException {
        // getCACaps
        ScepHttpResponse getCACapsResp = httpSend(Operation.GetCACaps);
        this.cACaps = CACaps.getInstance(new String(getCACapsResp.getContentBytes()));

        // getCACert
        ScepHttpResponse getCACertResp = httpSend(Operation.GetCACert);
        this.authorityCertStore = retrieveCACertStore(getCACertResp, cACertValidator);

        X509CertificateHolder certHolder;
        try {
            certHolder = new X509CertificateHolder(
                    this.authorityCertStore.getSignatureCert().getEncoded());
        } catch (CertificateEncodingException e) {
            throw new ScepClientException(e);
        } catch (IOException e) {
            throw new ScepClientException(e);
        }
        this.responseSignerCerts = new CollectionStore<X509CertificateHolder>(
                Arrays.asList(certHolder));
    }

    public CACaps getCACaps()
    throws ScepClientException {
        initIfNotInited();
        return cACaps;
    }

    public CAIdentifier getCAId()
    throws ScepClientException {
        initIfNotInited();
        return cAId;
    }

    public CACertValidator getCACertValidator()
    throws ScepClientException {
        initIfNotInited();
        return cACertValidator;
    }

    public AuthorityCertStore getAuthorityCertStore()
    throws ScepClientException {
        initIfNotInited();
        return authorityCertStore;
    }

    public X509CRL scepGetCRL(
            final PrivateKey identityKey,
            final X509Certificate identityCert,
            final X500Name issuer,
            final BigInteger serialNumber)
    throws ScepClientException {
        ParamUtil.assertNotNull("identityKey", identityKey);
        ParamUtil.assertNotNull("identityCert", identityCert);
        ParamUtil.assertNotNull("issuer", issuer);
        ParamUtil.assertNotNull("serialNumber", serialNumber);

        initIfNotInited();

        PkiMessage pkiMessage = new PkiMessage(TransactionId.randomTransactionId(),
                MessageType.GetCRL);
        IssuerAndSerialNumber isn = new IssuerAndSerialNumber(issuer, serialNumber);
        pkiMessage.setMessageData(isn);
        ContentInfo request = encryptThenSign(pkiMessage, identityKey, identityCert);
        ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, request);
        CMSSignedData cmsSignedData = parsePkiMessage(httpResp.getContentBytes());
        PkiMessage response = decode(cmsSignedData, identityKey, identityCert);
        ContentInfo messageData = (ContentInfo) response.getMessageData();
        try {
            return ScepUtil.getCRLFromPkiMessage(SignedData.getInstance(messageData.getContent()));
        } catch (CRLException e) {
            throw new ScepClientException(e.getMessage(), e);
        }
    }

    public List<X509Certificate> scepGetCert(
            final PrivateKey identityKey,
            final X509Certificate identityCert,
            final X500Name issuer,
            final BigInteger serialNumber)
    throws ScepClientException {
        ParamUtil.assertNotNull("identityKey", identityKey);
        ParamUtil.assertNotNull("identityCert", identityCert);
        ParamUtil.assertNotNull("issuer", issuer);
        ParamUtil.assertNotNull("serialNumber", serialNumber);

        initIfNotInited();

        PkiMessage request = new PkiMessage(TransactionId.randomTransactionId(),
                MessageType.GetCert);

        IssuerAndSerialNumber isn = new IssuerAndSerialNumber(issuer, serialNumber);
        request.setMessageData(isn);
        ContentInfo envRequest = encryptThenSign(request, identityKey, identityCert);
        ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, envRequest);

        CMSSignedData cmsSignedData = parsePkiMessage(httpResp.getContentBytes());
        DecodedPkiMessage response = decode(cmsSignedData, identityKey, identityCert);
        ContentInfo messageData = (ContentInfo) response.getMessageData();
        try {
            return ScepUtil.getCertsFromSignedData(
                    SignedData.getInstance(messageData.getContent()));
        } catch (CertificateException e) {
            throw new ScepClientException(e.getMessage(), e);
        }
    }

    public EnrolmentResponse scepCertPoll(
            final PrivateKey identityKey,
            final X509Certificate identityCert,
            final CertificationRequest csr,
            final X500Name issuer)
    throws ScepClientException {
        ParamUtil.assertNotNull("csr", csr);

        TransactionId tid;
        try {
            tid = TransactionId.sha1TransactionId(
                    csr.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        } catch (InvalidKeySpecException e) {
            throw new ScepClientException(e.getMessage(), e);
        }

        return scepCertPoll(identityKey, identityCert, tid, issuer,
                csr.getCertificationRequestInfo().getSubject());
    }

    public EnrolmentResponse scepCertPoll(
            final PrivateKey identityKey,
            final X509Certificate identityCert,
            final TransactionId transactionId,
            final X500Name issuer,
            final X500Name subject)
    throws ScepClientException {
        ParamUtil.assertNotNull("identityKey", identityKey);
        ParamUtil.assertNotNull("identityCert", identityCert);
        ParamUtil.assertNotNull("issuer", issuer);
        ParamUtil.assertNotNull("transactionId", transactionId);

        initIfNotInited();

        PkiMessage pkiMessage = new PkiMessage(transactionId, MessageType.CertPoll);

        IssuerAndSubject is = new IssuerAndSubject(issuer, subject);
        pkiMessage.setMessageData(is);
        ContentInfo envRequest = encryptThenSign(pkiMessage, identityKey, identityCert);
        ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, envRequest);
        CMSSignedData cmsSignedData = parsePkiMessage(httpResp.getContentBytes());
        DecodedPkiMessage response = decode(cmsSignedData, identityKey, identityCert);
        assertSameNonce(pkiMessage, response);
        return new EnrolmentResponse(response);
    }

    public EnrolmentResponse scepEnrol(
            final CertificationRequest csr,
            final PrivateKey identityKey,
            final X509Certificate identityCert)
    throws ScepClientException {
        ParamUtil.assertNotNull("csr", csr);
        ParamUtil.assertNotNull("identityKey", identityKey);
        ParamUtil.assertNotNull("identityCert", identityCert);

        initIfNotInited();

        // draft-nourse-scep
        if (!isGutmannScep()) {
            return scepPkcsReq(csr, identityKey, identityCert);
        }

        // draft-gutmann-scep
        if (!ScepUtil.isSelfSigned(identityCert)) {
            X509Certificate cACert = authorityCertStore.getCACert();
            if (identityCert.getIssuerX500Principal().equals(cACert.getSubjectX500Principal())) {
                if (cACaps.containsCapability(CACapability.Renewal)) {
                    return scepRenewalReq(csr, identityKey, identityCert);
                }
            } else {
                if (cACaps.containsCapability(CACapability.Update)) {
                    return scepUpdateReq(csr, identityKey, identityCert);
                }
            }
        } // end if

        return scepPkcsReq(csr, identityKey, identityCert);
    }

    public EnrolmentResponse scepPkcsReq(
            final CertificationRequest csr,
            final PrivateKey identityKey,
            final X509Certificate identityCert)
    throws ScepClientException {
        ParamUtil.assertNotNull("csr", csr);
        ParamUtil.assertNotNull("identityKey", identityKey);
        ParamUtil.assertNotNull("identityCert", identityCert);

        initIfNotInited();

        boolean selfSigned = ScepUtil.isSelfSigned(identityCert);
        if (!selfSigned) {
            throw new IllegalArgumentException("identityCert is not self-signed");
        }

        return doEnrol(MessageType.PKCSReq, csr, identityKey, identityCert);
    }

    public EnrolmentResponse scepRenewalReq(
            final CertificationRequest csr,
            final PrivateKey identityKey,
            final X509Certificate identityCert)
    throws ScepClientException {
        initIfNotInited();

        if (!cACaps.containsCapability(CACapability.Renewal)) {
            throw new OperationNotSupportedException(
                    "unsupported messageType '" + MessageType.RenewalReq + "'");
        }
        boolean selfSigned = ScepUtil.isSelfSigned(identityCert);
        if (selfSigned) {
            throw new IllegalArgumentException("identityCert could not be self-signed");
        }

        return doEnrol(MessageType.RenewalReq, csr, identityKey, identityCert);
    }

    public EnrolmentResponse scepUpdateReq(
            final CertificationRequest csr,
            final PrivateKey identityKey,
            final X509Certificate identityCert)
    throws ScepClientException {
        initIfNotInited();

        if (!cACaps.containsCapability(CACapability.Update)) {
            throw new OperationNotSupportedException(
                    "unsupported messageType '" + MessageType.UpdateReq + "'");
        }
        boolean selfSigned = ScepUtil.isSelfSigned(identityCert);
        if (selfSigned) {
            throw new IllegalArgumentException("identityCert could not be self-signed");
        }

        return doEnrol(MessageType.UpdateReq, csr, identityKey, identityCert);
    }

    private EnrolmentResponse doEnrol(
            final MessageType messageType,
            final CertificationRequest csr,
            final PrivateKey identityKey,
            final X509Certificate identityCert)
    throws ScepClientException {
        TransactionId tid;
        try {
            tid = TransactionId.sha1TransactionId(
                    csr.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        } catch (InvalidKeySpecException e) {
            throw new ScepClientException(e.getMessage(), e);
        }
        PkiMessage pkiMessage = new PkiMessage(tid, messageType);

        pkiMessage.setMessageData(csr);
        ContentInfo envRequest = encryptThenSign(pkiMessage, identityKey, identityCert);
        ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, envRequest);

        CMSSignedData cmsSignedData = parsePkiMessage(httpResp.getContentBytes());
        DecodedPkiMessage response = decode(cmsSignedData, identityKey, identityCert);
        assertSameNonce(pkiMessage, response);
        return new EnrolmentResponse(response);
    }

    public AuthorityCertStore scepNextCACert()
    throws ScepClientException {
        initIfNotInited();

        if (!this.cACaps.containsCapability(CACapability.GetNextCACert)) {
            throw new OperationNotSupportedException(
                    "unsupported operation '" + Operation.GetNextCACert.getCode() + "'");
        }

        ScepHttpResponse resp = httpSend(Operation.GetNextCACert);
        return retrieveNextCAAuthorityCertStore(resp);
    }

    private ContentInfo encryptThenSign(
            final PkiMessage request,
            final PrivateKey identityKey,
            final X509Certificate identityCert)
    throws ScepClientException {
        HashAlgoType hashAlgo = cACaps.getMostSecureHashAlgo();
        if (hashAlgo == HashAlgoType.MD5 && !useInsecureAlgorithms) {
            throw new ScepClientException(
                    "Scep server supports only MD5 but it not permitted in client");
        }
        String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(identityKey, hashAlgo);
        ASN1ObjectIdentifier encAlgId;
        if (cACaps.containsCapability(CACapability.AES)) {
            encAlgId = CMSAlgorithm.AES128_CBC;
        } else if (cACaps.containsCapability(CACapability.DES3)) {
            encAlgId = CMSAlgorithm.DES_EDE3_CBC;
        } else if (useInsecureAlgorithms) {
            encAlgId = CMSAlgorithm.DES_CBC;
        } else {    // no support of DES
            throw new ScepClientException("DES will not be supported by this client");
        }

        try {
            return request.encode(
                    identityKey,
                    signatureAlgorithm,
                    identityCert,
                    new X509Certificate[]{identityCert},
                    authorityCertStore.getEncryptionCert(),
                    encAlgId);
        } catch (MessageEncodingException e) {
            throw new ScepClientException(e);
        }
    }

    public void destroy() {
    }

    private AuthorityCertStore retrieveNextCAAuthorityCertStore(
            final ScepHttpResponse httpResp)
    throws ScepClientException {
        String ct = httpResp.getContentType();

        if (!ScepConstants.CT_x_x509_next_ca_cert.equalsIgnoreCase(ct)) {
            throw new ScepClientException("invalid Content-Type '" + ct + "'");
        }

        CMSSignedData cmsSignedData;
        try {
            cmsSignedData = new CMSSignedData(httpResp.getContentBytes());
        } catch (CMSException e) {
            throw new ScepClientException("invalid SignedData message: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            throw new ScepClientException("invalid SignedData message: " + e.getMessage(), e);
        }

        DecodedNextCAMessage resp;
        try {
            resp = DecodedNextCAMessage.decode(cmsSignedData, responseSignerCerts);
        } catch (MessageDecodingException e) {
            throw new ScepClientException("could not decode response: " + e.getMessage(), e);
        }

        if (resp.getFailureMessage() != null) {
            throw new ScepClientException("Error: " + resp.getFailureMessage());
        }

        Boolean b = resp.isSignatureValid();
        if (b != null && !b.booleanValue()) {
            throw new ScepClientException("Signature is invalid");
        }

        Date signingTime = resp.getSigningTime();
        long maxSigningTimeBias = getMaxSigningTimeBiasInMs();
        if (maxSigningTimeBias > 0) {
            if (signingTime == null) {
                throw new ScepClientException("CMS signingTime attribute is not present");
            }

            long now = System.currentTimeMillis();
            long diff = now - signingTime.getTime();
            if (diff < 0) {
                diff = -1 * diff;
            }
            if (diff > maxSigningTimeBias) {
                throw new ScepClientException("CMS signingTime is out of permitted period");
            }
        }

        if (!resp.getSignatureCert().equals(authorityCertStore.getSignatureCert())) {
            throw new ScepClientException("the signature certificate could not be trusted");
        }

        return resp.getAuthorityCertStore();
    } // method retrieveNextCAAuthorityCertStore

    private void initIfNotInited()
    throws ScepClientException {
        if (cACaps == null) {
            init();
        }
    }

    private DecodedPkiMessage decode(
            final CMSSignedData pkiMessage,
            final PrivateKey recipientKey,
            final X509Certificate recipientCert)
    throws ScepClientException {
        DecodedPkiMessage resp;
        try {
            resp = DecodedPkiMessage.decode(pkiMessage, recipientKey, recipientCert,
                    responseSignerCerts);
        } catch (MessageDecodingException e) {
            throw new ScepClientException(e);
        }

        if (resp.getFailureMessage() != null) {
            throw new ScepClientException("Error: " + resp.getFailureMessage());
        }

        Boolean b = resp.isSignatureValid();
        if (b != null && !b.booleanValue()) {
            throw new ScepClientException("Signature is invalid");
        }

        b = resp.isDecryptionSuccessful();
        if (b != null && !b.booleanValue()) {
            throw new ScepClientException("Decryption failed");
        }

        Date signingTime = resp.getSigningTime();
        long maxSigningTimeBias = getMaxSigningTimeBiasInMs();
        if (maxSigningTimeBias > 0) {
            if (signingTime == null) {
                throw new ScepClientException("CMS signingTime attribute is not present");
            }

            long now = System.currentTimeMillis();
            long diff = now - signingTime.getTime();
            if (diff < 0) {
                diff = -1 * diff;
            }
            if (diff > maxSigningTimeBias) {
                throw new ScepClientException("CMS signingTime is out of permitted period");
            }
        }

        if (!resp.getSignatureCert().equals(authorityCertStore.getSignatureCert())) {
            throw new ScepClientException("the signature certificate could not be trusted");
        }
        return resp;
    } // method decode

    private boolean isGutmannScep() {
        return cACaps.containsCapability(CACapability.AES)
                || cACaps.containsCapability(CACapability.Update);
    }

    private static X509Certificate parseCert(
            final byte[] certBytes)
    throws ScepClientException {
        try {
            return ScepUtil.parseCert(certBytes);
        } catch (IOException e) {
            throw new ScepClientException(e);
        } catch (CertificateException e) {
            throw new ScepClientException(e);
        }
    }

    private static CMSSignedData parsePkiMessage(
            final byte[] messageBytes)
    throws ScepClientException {
        try {
            return new CMSSignedData(messageBytes);
        } catch (CMSException e) {
            throw new ScepClientException(e);
        }
    }

    private static AuthorityCertStore retrieveCACertStore(
            final ScepHttpResponse resp,
            final CACertValidator cAValidator)
    throws ScepClientException {
        String ct = resp.getContentType();

        X509Certificate cACert = null;
        List<X509Certificate> rACerts = new LinkedList<X509Certificate>();

        if (ScepConstants.CT_x_x509_ca_cert.equalsIgnoreCase(ct)) {
            cACert = parseCert(resp.getContentBytes());
        } else if (ScepConstants.CT_x_x509_ca_ra_cert.equalsIgnoreCase(ct)) {
            ContentInfo contentInfo = ContentInfo.getInstance(resp.getContentBytes());

            SignedData signedData;
            try {
                signedData = SignedData.getInstance(contentInfo.getContent());
            } catch (IllegalArgumentException e) {
                throw new ScepClientException("invalid SignedData message: " + e.getMessage(), e);
            }

            List<X509Certificate> certs;
            try {
                certs = ScepUtil.getCertsFromSignedData(signedData);
            } catch (CertificateException e) {
                throw new ScepClientException(e.getMessage(), e);
            }

            final int n = certs.size();
            if (n < 2) {
                throw new ScepClientException(
                        "at least 2 certificates are expected, but only " + n + " is available");
            }

            for (int i = 0; i < n; i++) {
                X509Certificate c = certs.get(i);
                if (c.getBasicConstraints() > -1) {
                    if (cACert != null) {
                        throw new ScepClientException(
                                "multiple CA certificates is returned, but exactly 1 is expected");
                    }
                    cACert = c;
                } else {
                    rACerts.add(c);
                }
            }

            if (cACert == null) {
                throw new ScepClientException("no CA certificate is returned");
            }
        } else {
            throw new ScepClientException("invalid Content-Type '" + ct + "'");
        }

        if (!cAValidator.isTrusted(cACert)) {
            throw new ScepClientException(
                    "CA certificate '" + cACert.getSubjectX500Principal() + "' is not trusted");
        }

        if (rACerts.isEmpty()) {
            return AuthorityCertStore.getInstance(cACert);
        } else {
            AuthorityCertStore cs = AuthorityCertStore.getInstance(
                    cACert, rACerts.toArray(new X509Certificate[0]));
            X509Certificate rAEncCert = cs.getEncryptionCert();
            X509Certificate rASignCert = cs.getSignatureCert();
            try {
                if (!ScepUtil.issues(cACert, rAEncCert)) {
                    throw new ScepClientException("RA certificate '"
                            + rAEncCert.getSubjectX500Principal()
                            + " is not issued by the CA");
                }
                if (rASignCert != rAEncCert && ScepUtil.issues(cACert, rASignCert)) {
                    throw new ScepClientException("RA certificate '"
                            + rASignCert.getSubjectX500Principal()
                            + " is not issued by the CA");
                }
            } catch (CertificateException e) {
                throw new ScepClientException("invalid certificate: " + e.getMessage(), e);
            }
            return cs;
        }
    } // method retrieveCACertStore

    private static void assertSameNonce(
            final PkiMessage request,
            final PkiMessage response)
    throws ScepClientException {
        if (request.getSenderNonce().equals(response.getRecipientNonce())) {
            throw new ScepClientException(
                    "SenderNonce of the request and RecipientNonce of response are not the same");
        }
    }

}
