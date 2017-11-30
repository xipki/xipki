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

package org.xipki.litecaclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 */

public class CmpCaClient {

    private static final Logger LOG = LoggerFactory.getLogger(CmpCaClient.class);

    private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";

    private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

    private static final ASN1ObjectIdentifier id_xipki_cmp =
            new ASN1ObjectIdentifier("1.3.6.2.4.1.45522.2.2");

    private final Set<String> trustedProtectionAlgOids = new HashSet<>();

    private final URL caUrl;

    private final ContentSigner requestorSigner;

    private final X509Certificate responderCert;

    private final GeneralName requestorSubject;

    private final GeneralName responderSubject;

    private final String hashAlgo;

    private final SecureRandom random;

    private X509Certificate caCert;

    private byte[] caSubjectKeyIdentifier;

    private X500Name caSubject;

    // Use this constructor only if the CA server has Software XiPKI version 2.2.1 or later.
    public CmpCaClient(String caUrl,
            PrivateKey requestorKey, X509Certificate requestorCert, X509Certificate responderCert,
            String hashAlgo) throws Exception {
        this(caUrl, null, requestorKey, requestorCert, responderCert, hashAlgo);
    }

    public CmpCaClient(String caUrl, X509Certificate caCert,
            PrivateKey requestorKey, X509Certificate requestorCert, X509Certificate responderCert,
            String hashAlgo) throws Exception {
        this.caUrl = new URL(SdkUtil.requireNonBlank("caUrl", caUrl));

        SdkUtil.requireNonNull("requestorKey", requestorKey);
        SdkUtil.requireNonNull("requestorCert", requestorCert);

        this.hashAlgo = hashAlgo.replaceAll("-", "").toUpperCase();
        this.responderCert = SdkUtil.requireNonNull("responderCert", responderCert);
        this.random = new SecureRandom();

        X500Name x500Name = X500Name.getInstance(
                requestorCert.getSubjectX500Principal().getEncoded());
        this.requestorSubject = new GeneralName(x500Name);

        X500Name subject = X500Name.getInstance(
                responderCert.getSubjectX500Principal().getEncoded());
        this.responderSubject = new GeneralName(subject);
        this.requestorSigner = buildSigner(requestorKey);

        ASN1ObjectIdentifier[] oids = {
                PKCSObjectIdentifiers.sha256WithRSAEncryption,
                PKCSObjectIdentifiers.sha384WithRSAEncryption,
                PKCSObjectIdentifiers.sha512WithRSAEncryption,
                X9ObjectIdentifiers.ecdsa_with_SHA256,
                X9ObjectIdentifiers.ecdsa_with_SHA384,
                X9ObjectIdentifiers.ecdsa_with_SHA512,
                NISTObjectIdentifiers.dsa_with_sha256,
                NISTObjectIdentifiers.dsa_with_sha384,
                NISTObjectIdentifiers.dsa_with_sha512};
        for (ASN1ObjectIdentifier oid : oids) {
            trustedProtectionAlgOids.add(oid.getId());
        }

        if (caCert != null) {
            this.caCert = caCert;
            this.caSubject = X500Name.getInstance(
                    caCert.getSubjectX500Principal().getEncoded());
            this.caSubjectKeyIdentifier = SdkUtil.extractSki(caCert);
        }
    }

    public void init() throws Exception {
        TlsInit.init();

        if (caCert != null) {
            return;
        }

        Certificate tcert = cmpCaCerts()[0];
        this.caSubject = tcert.getSubject();
        this.caCert = SdkUtil.parseCert(tcert.getEncoded());
        this.caSubjectKeyIdentifier = SdkUtil.extractSki(this.caCert);
    }

    public void shutdown() {
        TlsInit.shutdown();
    }

    public X509Certificate getCaCert() {
        return caCert;
    }

    private byte[] randomTransactionId() {
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        return bytes;
    }

    private byte[] randomSenderNonce() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return bytes;
    }

    private Certificate[] cmpCaCerts() throws Exception {
        ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
                PKIHeader.CMP_2000, requestorSubject, responderSubject);
        builder.setMessageTime(new Date());
        builder.setTransactionID(randomTransactionId());
        builder.setSenderNonce(randomSenderNonce());

        InfoTypeAndValue itv = new InfoTypeAndValue(id_xipki_cmp);
        PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, new GenMsgContent(itv));
        builder.setBody(body);

        ProtectedPKIMessage request = builder.build(requestorSigner);
        PKIMessage response = transmit(request);
        ASN1Encodable asn1Value = extractGeneralRepContent(response, id_xipki_cmp.getId());
        ASN1Sequence seq = ASN1Sequence.getInstance(asn1Value);

        final int size = seq.size();
        Certificate[] cacerts = new Certificate[size];
        for (int i = 0; i < size; i++) {
            cacerts[i] = CMPCertificate.getInstance(seq.getObjectAt(i)).getX509v3PKCert();
        }
        return cacerts;
    }

    private ASN1Encodable extractGeneralRepContent(final PKIMessage response,
            final String expectedType) throws Exception {
        PKIBody respBody = response.getBody();
        int bodyType = respBody.getType();

        if (PKIBody.TYPE_ERROR == bodyType) {
            ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
            throw new Exception("Server returned PKIStatus: "
                    + buildText(content.getPKIStatusInfo()));
        } else if (PKIBody.TYPE_GEN_REP != bodyType) {
            throw new Exception(String.format(
                    "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
                    PKIBody.TYPE_GEN_REP, PKIBody.TYPE_ERROR));
        }

        GenRepContent genRep = GenRepContent.getInstance(respBody.getContent());

        InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
        InfoTypeAndValue itv = null;
        if (itvs != null && itvs.length > 0) {
            for (InfoTypeAndValue entry : itvs) {
                if (expectedType.equals(entry.getInfoType().getId())) {
                    itv = entry;
                    break;
                }
            }
        }
        if (itv == null) {
            throw new Exception("the response does not contain InfoTypeAndValue " + expectedType);
        }

        return itv.getInfoValue();
    } // method extractGeneralRepContent

    private boolean verifyProtection(GeneralPKIMessage pkiMessage)
            throws CMPException, InvalidKeyException, OperatorCreationException {
        ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

        if (protectedMsg.hasPasswordBasedMacProtection()) {
            LOG.warn("protection is not signature based: "
                    + pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
            return false;
        }

        PKIHeader header = protectedMsg.getHeader();
        if (!header.getSender().equals(responderSubject)) {
            LOG.warn("not authorized responder '{}'", header.getSender());
            return false;
        }

        String algOid = protectedMsg.getHeader().getProtectionAlg().getAlgorithm().getId();
        if (!trustedProtectionAlgOids.contains(algOid)) {
            LOG.warn("PKI protection algorithm is untrusted '{}'", algOid);
            return false;
        }

        ContentVerifierProvider verifierProvider = getContentVerifierProvider(
                responderCert.getPublicKey());
        if (verifierProvider == null) {
            LOG.warn("not authorized responder '{}'", header.getSender());
            return false;
        }

        return protectedMsg.verify(verifierProvider);
    } // method verifyProtection

    public static ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
            throws InvalidKeyException {
        SdkUtil.requireNonNull("publicKey", publicKey);

        String keyAlg = publicKey.getAlgorithm().toUpperCase();

        DigestAlgorithmIdentifierFinder digAlgFinder =
                new DefaultDigestAlgorithmIdentifierFinder();
        BcContentVerifierProviderBuilder builder;
        if ("RSA".equals(keyAlg)) {
            builder = new BcRSAContentVerifierProviderBuilder(digAlgFinder);
        } else if ("DSA".equals(keyAlg)) {
            builder = new BcDSAContentVerifierProviderBuilder(digAlgFinder);
        } else if ("EC".equals(keyAlg) || "ECDSA".equals(keyAlg)) {
            builder = new BcECContentVerifierProviderBuilder(digAlgFinder);
        } else {
            throw new InvalidKeyException("unknown key algorithm of the public key " + keyAlg);
        }

        AsymmetricKeyParameter keyParam;
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
            keyParam = new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
        } else if (publicKey instanceof ECPublicKey) {
            keyParam = ECUtil.generatePublicKeyParameter(publicKey);
        } else if (publicKey instanceof DSAPublicKey) {
            keyParam = DSAUtil.generatePublicKeyParameter(publicKey);
        } else {
            throw new InvalidKeyException("unknown key " + publicKey.getClass().getName());
        }

        try {
            return builder.build(keyParam);
        } catch (OperatorCreationException ex) {
            throw new InvalidKeyException("could not build ContentVerifierProvider: "
                    + ex.getMessage(), ex);
        }
    }

    private PKIMessage transmit(ProtectedPKIMessage request) throws Exception {
        byte[] encodedResponse = send(request.toASN1Structure().getEncoded());
        GeneralPKIMessage response = new GeneralPKIMessage(encodedResponse);

        PKIHeader reqHeader = request.getHeader();
        PKIHeader respHeader = response.getHeader();
        ASN1OctetString tid = reqHeader.getTransactionID();
        if (!tid.equals(respHeader.getTransactionID())) {
            throw new Exception("response.transactionId != request.transactionId");
        }

        ASN1OctetString senderNonce = reqHeader.getSenderNonce();
        if (!senderNonce.equals(respHeader.getRecipNonce())) {
            throw new Exception("response.recipientNonce != request.senderNonce");
        }

        GeneralName rec = respHeader.getRecipient();
        if (!requestorSubject.equals(rec)) {
            throw new Exception("unknown CMP requestor " + rec.toString());
        }

        if (!response.hasProtection()) {
            PKIBody respBody = response.getBody();
            int bodyType = respBody.getType();
            if (bodyType != PKIBody.TYPE_ERROR) {
                throw new Exception("response is not signed");
            }
        }

        if (verifyProtection(response)) {
            return response.toASN1Structure();
        }

        throw new Exception("invalid signature in PKI protection");
    }

    private X509Certificate parseEnrollCertResult(PKIMessage response) throws Exception {
        PKIBody respBody = response.getBody();
        final int bodyType = respBody.getType();

        if (PKIBody.TYPE_ERROR == bodyType) {
            ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
            throw new Exception("Server returned PKIStatus: "
                    + buildText(content.getPKIStatusInfo()));
        } else if (PKIBody.TYPE_CERT_REP != bodyType) {
            throw new Exception(String.format(
                    "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
                    PKIBody.TYPE_CERT_REP, PKIBody.TYPE_ERROR));
        }

        CertRepMessage certRep = CertRepMessage.getInstance(respBody.getContent());
        CertResponse[] certResponses = certRep.getResponse();

        if (certResponses.length != 1) {
            throw new Exception("expected 1 CertResponse, but returned " + certResponses.length);
        }

        // We only accept the certificates which are requested.
        CertResponse certResp = certResponses[0];
        PKIStatusInfo statusInfo = certResp.getStatus();
        int status = statusInfo.getStatus().intValue();

        if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
            throw new Exception("Server returned PKIStatus: " + buildText(statusInfo));
        }

        CertifiedKeyPair cvk = certResp.getCertifiedKeyPair();
        if (cvk != null) {
            CMPCertificate cmpCert = cvk.getCertOrEncCert().getCertificate();
            if (cmpCert != null) {
                X509Certificate cert = SdkUtil.parseCert(cmpCert.getX509v3PKCert().getEncoded());
                if (!verify(caCert, cert)) {
                    throw new Exception("The returned certificate is not issued by the given CA");
                }

                return cert;
            }
        }

        throw new Exception("Server did not return any certificate");
    } // method parseEnrollCertResult

    public X509Certificate requestCertViaCSR(String certProfile, CertificationRequest csr)
            throws Exception {
        ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
                PKIHeader.CMP_2000, requestorSubject, responderSubject);
        builder.setMessageTime(new Date());
        builder.setTransactionID(randomTransactionId());
        builder.setSenderNonce(randomSenderNonce());

        builder.addGeneralInfo(
                new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
        builder.addGeneralInfo(
                new InfoTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                        new DERUTF8String("CERT-PROFILE?" + certProfile + "%")));
        builder.setBody(new PKIBody(PKIBody.TYPE_P10_CERT_REQ, csr));
        ProtectedPKIMessage request = builder.build(requestorSigner);

        PKIMessage response = transmit(request);
        return parseEnrollCertResult(response);
    }

    private boolean parseRevocationResult(PKIMessage response, BigInteger serialNumber)
            throws Exception {
        PKIBody respBody = response.getBody();
        final int bodyType = respBody.getType();

        if (PKIBody.TYPE_ERROR == bodyType) {
            ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
            throw new Exception("Server returned PKIStatus: " + content.getPKIStatusInfo());
        } else if (PKIBody.TYPE_REVOCATION_REP != bodyType) {
            throw new Exception(String.format(
                    "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
                    PKIBody.TYPE_REVOCATION_REP, PKIBody.TYPE_ERROR));
        }

        RevRepContent content = RevRepContent.getInstance(respBody.getContent());
        PKIStatusInfo[] statuses = content.getStatus();
        int statusesLen = (statuses == null) ? 0 : statuses.length;
        if (statusesLen != 1) {
            throw new Exception(String.format(
                "incorrect number of status entries in response '%s' instead the expected '1'",
                statusesLen));
        }

        PKIStatusInfo statusInfo = statuses[0];
        int status = statusInfo.getStatus().intValue();

        if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
            LOG.warn("Server returned error: " + buildText(statusInfo));
            return false;
        }

        CertId[] revCerts = content.getRevCerts();
        if (revCerts == null) {
            return true;
        }

        CertId revCert = revCerts[0];
        return caSubject.equals(revCert.getIssuer().getName())
                && serialNumber.equals(revCert.getSerialNumber().getValue());
    }

    public X509Certificate requestCertViaCRMF(String certProfile, PrivateKey privateKey,
            SubjectPublicKeyInfo publicKeyInfo, String subject) throws Exception {
        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

        certTemplateBuilder.setSubject(new X500Name(subject));
        certTemplateBuilder.setPublicKey(publicKeyInfo);

        CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(), null);

        ProofOfPossessionSigningKeyBuilder popoBuilder
                = new ProofOfPossessionSigningKeyBuilder(certReq);

        ContentSigner popoSigner = buildSigner(privateKey);
        POPOSigningKey popoSk = popoBuilder.build(popoSigner);
        ProofOfPossession popo = new ProofOfPossession(popoSk);

        AttributeTypeAndValue certprofileInfo =
                new AttributeTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                        new DERUTF8String("CERT-PROFILE?" + certProfile + "%"));

        AttributeTypeAndValue[] atvs = new AttributeTypeAndValue[]{certprofileInfo};
        CertReqMsg certReqMsg = new CertReqMsg(certReq, popo, atvs);

        PKIBody body = new PKIBody(PKIBody.TYPE_CERT_REQ, new CertReqMessages(certReqMsg));
        ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
                PKIHeader.CMP_2000, requestorSubject, responderSubject);
        builder.setMessageTime(new Date());
        builder.setTransactionID(randomTransactionId());
        builder.setSenderNonce(randomSenderNonce());

        builder.addGeneralInfo(
                new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
        builder.setBody(body);

        ProtectedPKIMessage request = builder.build(requestorSigner);
        PKIMessage response = transmit(request);
        return parseEnrollCertResult(response);
    } // method requestCerts

    public boolean revokeCert(BigInteger serialNumber, CRLReason reason) throws Exception {
        ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
                PKIHeader.CMP_2000, requestorSubject, responderSubject);
        builder.setMessageTime(new Date());
        builder.setTransactionID(randomTransactionId());
        builder.setSenderNonce(randomSenderNonce());

        CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
        certTempBuilder.setIssuer(caSubject);
        certTempBuilder.setSerialNumber(new ASN1Integer(serialNumber));

        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(caSubjectKeyIdentifier);
        byte[] encodedAki = aki.getEncoded();

        Extension extAki = new Extension(Extension.authorityKeyIdentifier, false, encodedAki);
        Extensions certTempExts = new Extensions(extAki);
        certTempBuilder.setExtensions(certTempExts);

        ASN1Enumerated asn1Reason = new ASN1Enumerated(reason.getValue().intValue());
        Extensions exts = new Extensions(
                new Extension(Extension.reasonCode, true,
                        new DEROctetString(asn1Reason.getEncoded())));
        RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);

        RevReqContent content = new RevReqContent(revDetails);
        builder.setBody(new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content));
        ProtectedPKIMessage request = builder.build(requestorSigner);

        PKIMessage response = transmit(request);
        return parseRevocationResult(response, serialNumber);
    }

    private boolean verify(X509Certificate caCert, X509Certificate cert) {
        if (!cert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())) {
            return false;
        }

        PublicKey caPublicKey = caCert.getPublicKey();
        try {
            cert.verify(caPublicKey);
            return true;
        } catch (Exception ex) {
            LOG.debug("{} while verifying signature: {}", ex.getClass().getName(), ex.getMessage());
            return false;
        }
    } // method verify

    public boolean unrevokeCert(BigInteger serialNumber)
            throws Exception {
        return revokeCert(serialNumber, CRLReason.lookup(CRLReason.removeFromCRL));
    }

    public byte[] send(byte[] request) throws IOException {
        SdkUtil.requireNonNull("request", request);
        HttpURLConnection httpUrlConnection = SdkUtil.openHttpConn(caUrl);
        httpUrlConnection.setDoOutput(true);
        httpUrlConnection.setUseCaches(false);

        httpUrlConnection.setRequestMethod("POST");
        httpUrlConnection.setRequestProperty("Content-Type", CMP_REQUEST_MIMETYPE);
        httpUrlConnection.setRequestProperty("Content-Length", Integer.toString(request.length));
        OutputStream outputstream = httpUrlConnection.getOutputStream();
        outputstream.write(request);
        outputstream.flush();

        InputStream inputStream = httpUrlConnection.getInputStream();
        if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            inputStream.close();
            throw new IOException("bad response: " + httpUrlConnection.getResponseCode() + "    "
                    + httpUrlConnection.getResponseMessage());
        }
        String responseContentType = httpUrlConnection.getContentType();
        boolean isValidContentType = false;
        if (responseContentType != null) {
            if (responseContentType.equalsIgnoreCase(CMP_RESPONSE_MIMETYPE)) {
                isValidContentType = true;
            }
        }
        if (!isValidContentType) {
            inputStream.close();
            throw new IOException("bad response: mime type " + responseContentType
                    + " not supported!");
        }

        return SdkUtil.read(inputStream);
    } // method send

    private ContentSigner buildSigner(PrivateKey signingKey) throws OperatorCreationException {
        String keyAlgo = signingKey.getAlgorithm();
        String sigAlgo;
        if ("EC".equalsIgnoreCase(keyAlgo)) {
            sigAlgo = hashAlgo + "WITHECDSA";
        } else {
            sigAlgo = hashAlgo + "WITH" + keyAlgo;
        }
        return new JcaContentSignerBuilder(sigAlgo).build(signingKey);
    }

    private static String buildText(PKIStatusInfo pkiStatusInfo) {
        final int status = pkiStatusInfo.getStatus().intValue();
        switch (status) {
            case 0: return "accepted (0)";
            case 1: return "grantedWithMods (1)";
            case 2: return "rejection (2)";
            case 3: return "waiting (3)";
            case 4: return "revocationWarning (4)";
            case 5: return "revocationNotification (5)";
            case 6: return "keyUpdateWarning (6)";
            default: return Integer.toString(status);
        }
    }
}
