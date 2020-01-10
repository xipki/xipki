/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
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
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CA client which communicates with CA via CMP.
 *
 * @author Lijun Liao
 */

public abstract class CmpCaClient implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(CmpCaClient.class);

  private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";

  private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

  private static final ASN1ObjectIdentifier id_xipki_cmp_cacertchain =
      new ASN1ObjectIdentifier("1.3.6.1.4.1.45522.2.2");

  private static final int CMP_ACTION_CACERTCHAIN = 4;

  private final URL caUrl;

  private final String caUri;

  private final String hashAlgo;

  private final GeneralName requestorSubject;

  protected final GeneralName responderSubject;

  private final SecureRandom random;

  private X509Certificate caCert;

  private List<X509Certificate> caCertchain;

  private byte[] caSubjectKeyIdentifier;

  private X500Name caSubject;

  public CmpCaClient(String caUri, X509Certificate caCert, X500Name requestorSubject,
      X500Name responderSubject, String hashAlgo) throws Exception {
    this.caUri = SdkUtil.requireNonBlank("caUri", caUri);
    this.caUrl = new URL(this.caUri);
    this.hashAlgo = (hashAlgo == null) ? "SHA256" : hashAlgo;

    this.random = new SecureRandom();

    this.requestorSubject = new GeneralName(requestorSubject);
    this.responderSubject = new GeneralName(responderSubject);

    if (caCert != null) {
      this.caCert = caCert;
      this.caSubject = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
      this.caSubjectKeyIdentifier = SdkUtil.extractSki(caCert);
    }
  } // constructor

  public void init() throws Exception {
    TlsInit.init();

    if (caCert != null) {
      return;
    }

    Certificate[] certchain = cmpCaCerts();
    this.caCertchain = new ArrayList<>(certchain.length);
    for (Certificate m : certchain) {
      this.caCertchain.add(
          SdkUtil.parseCert((m.getEncoded())));
    }

    this.caCert = this.caCertchain.get(0);
    this.caSubject = certchain[0].getSubject();
    this.caSubjectKeyIdentifier = SdkUtil.extractSki(this.caCert);
  } // method init

  @Override
  public void close() {
    TlsInit.close();
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

  protected abstract ProtectedPKIMessage build(ProtectedPKIMessageBuilder builder) throws Exception;

  private Certificate[] cmpCaCerts() throws Exception {
    ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
        PKIHeader.CMP_2000, requestorSubject, responderSubject);
    builder.setMessageTime(new Date());
    builder.setTransactionID(randomTransactionId());
    builder.setSenderNonce(randomSenderNonce());

    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1Integer(CMP_ACTION_CACERTCHAIN));

    InfoTypeAndValue itv = new InfoTypeAndValue(id_xipki_cmp_cacertchain, new DERSequence(vec));
    PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, new GenMsgContent(itv));
    builder.setBody(body);

    ProtectedPKIMessage request = build(builder);
    PKIMessage response = transmit(request, null);
    ASN1Encodable asn1Value = extractGeneralRepContent(response, id_xipki_cmp_cacertchain.getId());
    ASN1Sequence seq = ASN1Sequence.getInstance(asn1Value);

    final int size = seq.size();
    Certificate[] caCerts = new Certificate[size];
    for (int i = 0; i < size; i++) {
      caCerts[i] = CMPCertificate.getInstance(seq.getObjectAt(i)).getX509v3PKCert();
    }
    return caCerts;
  } // method cmpCaCerts

  private ASN1Encodable extractGeneralRepContent(PKIMessage response, String expectedType)
      throws Exception {
    PKIBody respBody = response.getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new Exception("Server returned PKIStatus: " + buildText(content.getPKIStatusInfo()));
    } else if (PKIBody.TYPE_GEN_REP != bodyType) {
      throw new Exception(String.format("unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, PKIBody.TYPE_GEN_REP, PKIBody.TYPE_ERROR));
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

  protected abstract boolean verifyProtection(GeneralPKIMessage pkiMessage) throws Exception;

  private PKIMessage transmit(ProtectedPKIMessage request, String uri) throws Exception {
    byte[] encodedResponse = send(request.toASN1Structure().getEncoded(), uri);
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
      } else {
        return response.toASN1Structure();
      }
    }

    if (verifyProtection(response)) {
      return response.toASN1Structure();
    }

    throw new Exception("invalid signature/MAC in PKI protection");
  } // method transmit

  private Map<BigInteger, KeyAndCert> parseEnrollCertResult(PKIMessage response,
      int resonseBodyType, int numCerts) throws Exception {
    PKIBody respBody = response.getBody();
    final int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new Exception("Server returned PKIStatus: " + buildText(content.getPKIStatusInfo()));
    } else if (resonseBodyType != bodyType) {
      throw new Exception(String.format("unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, resonseBodyType, PKIBody.TYPE_ERROR));
    }

    CertRepMessage certRep = CertRepMessage.getInstance(respBody.getContent());
    CertResponse[] certResponses = certRep.getResponse();

    if (certResponses.length != numCerts) {
      throw new Exception("expected " + numCerts + " CertResponse, but returned "
          + certResponses.length);
    }

    // We only accept the certificates which are requested.
    Map<BigInteger, KeyAndCert> keycerts = new HashMap<>(numCerts * 2);
    for (int i = 0; i < numCerts; i++) {
      CertResponse certResp = certResponses[i];
      PKIStatusInfo statusInfo = certResp.getStatus();
      int status = statusInfo.getStatus().intValue();
      BigInteger certReqId = certResp.getCertReqId().getValue();

      if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
        throw new Exception("CertReqId " + certReqId
            + ": server returned PKIStatus: " + buildText(statusInfo));
      }

      CertifiedKeyPair cvk = certResp.getCertifiedKeyPair();
      if (cvk != null) {
        CMPCertificate cmpCert = cvk.getCertOrEncCert().getCertificate();
        X509Certificate cert = SdkUtil.parseCert(cmpCert.getX509v3PKCert().getEncoded());
        if (!verify(caCert, cert)) {
          throw new Exception("CertReqId " + certReqId
              + ": the returned certificate is not issued by the given CA");
        }

        EncryptedValue encKey = cvk.getPrivateKey();
        PrivateKeyInfo key = null;
        if (encKey != null) {
          byte[] keyBytes = decrypt(encKey);
          key = PrivateKeyInfo.getInstance(keyBytes);
        }

        keycerts.put(certReqId, new KeyAndCert(key, cert));
      }
    }

    return keycerts;
  } // method parseEnrollCertResult

  public X509Certificate enrollCertViaCsr(String certprofile, CertificationRequest csr,
      boolean profileInUri) throws Exception {
    ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
        PKIHeader.CMP_2000, requestorSubject, responderSubject);
    builder.setMessageTime(new Date());
    builder.setTransactionID(randomTransactionId());
    builder.setSenderNonce(randomSenderNonce());

    builder.addGeneralInfo(
        new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
    String uri = null;
    if (profileInUri) {
      uri = caUri + "?certprofile=" + certprofile.toLowerCase();
    } else {
      builder.addGeneralInfo(
          new InfoTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
              new DERUTF8String("certprofile?" + certprofile + "%")));
    }
    builder.setBody(new PKIBody(PKIBody.TYPE_P10_CERT_REQ, csr));
    ProtectedPKIMessage request = build(builder);

    PKIMessage response = transmit(request, uri);
    return parseEnrollCertResult(response, PKIBody.TYPE_CERT_REP, 1)
            .values().iterator().next().getCert();
  } // method enrollCertViaCsr

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
      throw new Exception(String.format("incorrect number of status entries in response '%s'"
          + " instead the expected '1'", statusesLen));
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
  } // method parseRevocationResult

  public X509Certificate enrollCertViaCrmf(String certprofile, PrivateKey privateKey,
      SubjectPublicKeyInfo publicKeyInfo, String subject, boolean profileInUri)
          throws Exception {
    return enrollCertsViaCrmf(new String[]{certprofile}, new PrivateKey[]{privateKey},
        new SubjectPublicKeyInfo[] {publicKeyInfo}, new String[] {subject}, profileInUri)[0];
  } // method enrollCertViaCrmf

  public X509Certificate[] enrollCertsViaCrmf(String[] certprofiles, PrivateKey[] privateKey,
      SubjectPublicKeyInfo[] publicKeyInfo, String[] subject, boolean profileInUri)
          throws Exception {
    final int n = certprofiles.length;

    String uri = null;
    if (profileInUri) {
      if (n > 1) {
        for (int i = 1; i < n; i++) {
          if (!certprofiles[0].equalsIgnoreCase(certprofiles[i])) {
            throw new IllegalArgumentException("not all certprofiles are of the same");
          }
        }
      }
      uri = caUri + "?certprofile=" + certprofiles[0];
    }

    CertReqMsg[] certReqMsgs = new CertReqMsg[n];
    BigInteger[] certReqIds = new BigInteger[n];

    for (int i = 0; i < n; i++) {
      certReqIds[i] = BigInteger.valueOf(i + 1);

      CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
      certTemplateBuilder.setSubject(new X500Name(subject[i]));
      certTemplateBuilder.setPublicKey(publicKeyInfo[i]);
      CertRequest certReq = new CertRequest(new ASN1Integer(certReqIds[i]),
          certTemplateBuilder.build(), null);
      ProofOfPossessionSigningKeyBuilder popoBuilder
          = new ProofOfPossessionSigningKeyBuilder(certReq);
      ContentSigner popoSigner = buildSigner(privateKey[i]);
      POPOSigningKey popoSk = popoBuilder.build(popoSigner);
      ProofOfPossession popo = new ProofOfPossession(popoSk);

      AttributeTypeAndValue[] atvs = null;
      if (uri == null) {
        AttributeTypeAndValue certprofileInfo =
            new AttributeTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                new DERUTF8String("certprofile?" + certprofiles[i] + "%"));
        atvs = new AttributeTypeAndValue[]{certprofileInfo};
      }
      certReqMsgs[i] = new CertReqMsg(certReq, popo, atvs);
    }

    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_REQ, new CertReqMessages(certReqMsgs));
    ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
        PKIHeader.CMP_2000, requestorSubject, responderSubject);
    builder.setMessageTime(new Date());
    builder.setTransactionID(randomTransactionId());
    builder.setSenderNonce(randomSenderNonce());

    builder.addGeneralInfo(
        new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
    builder.setBody(body);

    ProtectedPKIMessage request = build(builder);
    PKIMessage response = transmit(request, uri);
    Map<BigInteger, KeyAndCert> keyCerts =
        parseEnrollCertResult(response, PKIBody.TYPE_CERT_REP, n);

    X509Certificate[] ret = new X509Certificate[n];
    for (int i = 0; i < n; i++) {
      BigInteger certReqId = certReqIds[i];
      ret[i] = keyCerts.get(certReqId).getCert();
    }

    return ret;
  } // method enrollCertsViaCrmf

  public KeyAndCert enrollCertViaCrmfCaGenKeypair(String certprofile, String subject,
      boolean profileAndMetaInUri) throws Exception {
    return enrollCertsViaCrmfCaGenKeypair(new String[]{certprofile},
        new String[] {subject}, profileAndMetaInUri)[0];
  } // method enrollCertViaCrmfCaGenKeypair

  public KeyAndCert[] enrollCertsViaCrmfCaGenKeypair(String[] certprofiles,
      String[] subject, boolean profileAndMetaInUri) throws Exception {
    final int n = certprofiles.length;

    String uri = null;
    if (profileAndMetaInUri) {
      if (n > 1) {
        for (int i = 1; i < n; i++) {
          if (!certprofiles[0].equalsIgnoreCase(certprofiles[i])) {
            throw new IllegalArgumentException("not all certprofiles are of the same");
          }
        }
      }

      uri = caUri + "?certprofile=" + certprofiles[0] + "&ca-generate-keypair=true";
    }

    CertReqMsg[] certReqMsgs = new CertReqMsg[n];
    BigInteger[] certReqIds = new BigInteger[n];

    for (int i = 0; i < n; i++) {
      certReqIds[i] = BigInteger.valueOf(i + 1);

      CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
      certTemplateBuilder.setSubject(new X500Name(subject[i]));
      CertRequest certReq = new CertRequest(new ASN1Integer(certReqIds[i]),
          certTemplateBuilder.build(), null);

      AttributeTypeAndValue[] atvs = null;
      if (uri == null) {
        String utf8pairs = "certprofile?" + certprofiles[i] + "%"
            + "ca-generate-keypair?true%";

        AttributeTypeAndValue certprofileInfo =
            new AttributeTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                new DERUTF8String(utf8pairs));
        atvs = new AttributeTypeAndValue[]{certprofileInfo};
      }

      certReqMsgs[i] = new CertReqMsg(certReq, null, atvs);
    }

    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_REQ, new CertReqMessages(certReqMsgs));
    ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
        PKIHeader.CMP_2000, requestorSubject, responderSubject);
    builder.setMessageTime(new Date());
    builder.setTransactionID(randomTransactionId());
    builder.setSenderNonce(randomSenderNonce());

    builder.addGeneralInfo(
        new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
    builder.setBody(body);

    ProtectedPKIMessage request = build(builder);
    PKIMessage response = transmit(request, uri);
    Map<BigInteger, KeyAndCert> keyCerts =
        parseEnrollCertResult(response, PKIBody.TYPE_CERT_REP, n);

    KeyAndCert[] ret = new KeyAndCert[n];
    for (int i = 0; i < n; i++) {
      ret[i] = keyCerts.get(certReqIds[i]);
    }

    return ret;
  } // method enrollCertsViaCrmfCaGenKeypair

  public X509Certificate updateCertViaCrmf(PrivateKey privateKey, X500Name issuer,
      BigInteger oldCertSerialNumber) throws Exception {
    return updateCertsViaCrmf(new PrivateKey[]{privateKey}, issuer,
        new BigInteger[] {oldCertSerialNumber})[0];
  }

  public X509Certificate[] updateCertsViaCrmf(PrivateKey[] privateKey,
      X500Name issuer, BigInteger[] oldCertSerialNumbers) throws Exception {
    final int n = privateKey.length;

    CertReqMsg[] certReqMsgs = new CertReqMsg[n];
    BigInteger[] certReqIds = new BigInteger[n];
    GeneralName issuerGn = new GeneralName(issuer);

    for (int i = 0; i < n; i++) {
      certReqIds[i] = BigInteger.valueOf(i + 1);

      CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
      CertId certId = new CertId(issuerGn, oldCertSerialNumbers[i]);
      Controls controls = new Controls(
          new AttributeTypeAndValue(CMPObjectIdentifiers.regCtrl_oldCertID, certId));
      CertRequest certReq = new CertRequest(new ASN1Integer(certReqIds[i]),
          certTemplateBuilder.build(), controls);
      ProofOfPossessionSigningKeyBuilder popoBuilder
          = new ProofOfPossessionSigningKeyBuilder(certReq);
      ContentSigner popoSigner = buildSigner(privateKey[i]);
      POPOSigningKey popoSk = popoBuilder.build(popoSigner);
      ProofOfPossession popo = new ProofOfPossession(popoSk);

      certReqMsgs[i] = new CertReqMsg(certReq, popo, null);
    }

    PKIBody body = new PKIBody(PKIBody.TYPE_KEY_UPDATE_REQ, new CertReqMessages(certReqMsgs));
    ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
        PKIHeader.CMP_2000, requestorSubject, responderSubject);
    builder.setMessageTime(new Date());
    builder.setTransactionID(randomTransactionId());
    builder.setSenderNonce(randomSenderNonce());

    builder.addGeneralInfo(
        new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
    builder.setBody(body);

    ProtectedPKIMessage request = build(builder);
    PKIMessage response = transmit(request, caUri);
    Map<BigInteger, KeyAndCert> keyCerts =
        parseEnrollCertResult(response, PKIBody.TYPE_KEY_UPDATE_REP, n);

    X509Certificate[] ret = new X509Certificate[n];
    for (int i = 0; i < n; i++) {
      BigInteger certReqId = certReqIds[i];
      ret[i] = keyCerts.get(certReqId).getCert();
    }

    return ret;
  } // method updateCertsViaCrmf

  public KeyAndCert updateCertViaCrmfCaGenKeypair(X500Name issuer, BigInteger oldCertSerialNumber,
      boolean profileAndMetaInUri) throws Exception {
    return updateCertsViaCrmfCaGenKeypair(issuer, new BigInteger[] {oldCertSerialNumber},
        profileAndMetaInUri)[0];
  }

  public KeyAndCert[] updateCertsViaCrmfCaGenKeypair(X500Name issuer,
      BigInteger[] oldCertSerialNumbers, boolean profileAndMetaInUri) throws Exception {
    final int n = oldCertSerialNumbers.length;

    CertReqMsg[] certReqMsgs = new CertReqMsg[n];
    BigInteger[] certReqIds = new BigInteger[n];
    GeneralName issuerGn = new GeneralName(issuer);

    for (int i = 0; i < n; i++) {
      certReqIds[i] = BigInteger.valueOf(i + 1);

      CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
      CertId certId = new CertId(issuerGn, oldCertSerialNumbers[i]);
      Controls controls = new Controls(
          new AttributeTypeAndValue(CMPObjectIdentifiers.regCtrl_oldCertID, certId));
      CertRequest certReq = new CertRequest(new ASN1Integer(certReqIds[i]),
          certTemplateBuilder.build(), controls);

      AttributeTypeAndValue[] atvs = null;
      if (!profileAndMetaInUri) {
        String utf8pairs = "ca-generate-keypair?true%";

        AttributeTypeAndValue certprofileInfo =
            new AttributeTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                new DERUTF8String(utf8pairs));
        atvs = new AttributeTypeAndValue[]{certprofileInfo};
      }

      certReqMsgs[i] = new CertReqMsg(certReq, null, atvs);
    }

    PKIBody body = new PKIBody(PKIBody.TYPE_KEY_UPDATE_REQ, new CertReqMessages(certReqMsgs));
    ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
        PKIHeader.CMP_2000, requestorSubject, responderSubject);
    builder.setMessageTime(new Date());
    builder.setTransactionID(randomTransactionId());
    builder.setSenderNonce(randomSenderNonce());

    builder.addGeneralInfo(
        new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
    builder.setBody(body);

    ProtectedPKIMessage request = build(builder);

    String uri = profileAndMetaInUri ? caUri + "?ca-generate-keypair=true" : caUri;
    PKIMessage response = transmit(request, uri);

    Map<BigInteger, KeyAndCert> keyCerts =
        parseEnrollCertResult(response, PKIBody.TYPE_KEY_UPDATE_REP, n);

    KeyAndCert[] ret = new KeyAndCert[n];
    for (int i = 0; i < n; i++) {
      BigInteger certReqId = certReqIds[i];
      ret[i] = keyCerts.get(certReqId);
    }

    return ret;
  } // updateCertsViaCrmfCaGenKeypair

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
        new Extension(Extension.reasonCode, true, new DEROctetString(asn1Reason.getEncoded())));
    RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);

    RevReqContent content = new RevReqContent(revDetails);
    builder.setBody(new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content));
    ProtectedPKIMessage request = build(builder);

    PKIMessage response = transmit(request, null);
    return parseRevocationResult(response, serialNumber);
  } // method revokeCert

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

  public boolean unrevokeCert(BigInteger serialNumber) throws Exception {
    return revokeCert(serialNumber, CRLReason.lookup(CRLReason.removeFromCRL));
  }

  public byte[] send(byte[] request, String uri) throws IOException {
    URL url = ((uri == null) ? caUrl : new URL(uri));
    return SdkUtil.send(url, "POST", request, CMP_REQUEST_MIMETYPE, CMP_RESPONSE_MIMETYPE);
  } // method send

  protected abstract byte[] decrypt(EncryptedValue ev) throws Exception;

  protected ContentSigner buildSigner(PrivateKey signingKey) throws OperatorCreationException {
    String keyAlgo = signingKey.getAlgorithm().toUpperCase();
    String sigAlgo = "EC".equals(keyAlgo) ? hashAlgo + "WITHECDSA" : hashAlgo + "WITH" + keyAlgo;
    return new JcaContentSignerBuilder(sigAlgo).build(signingKey);
  }

  private static String buildText(PKIStatusInfo pkiStatusInfo) {
    final int status = pkiStatusInfo.getStatus().intValue();
    switch (status) {
      case 0:
        return "accepted (0)";
      case 1:
        return "grantedWithMods (1)";
      case 2:
        return "rejection (2)";
      case 3:
        return "waiting (3)";
      case 4:
        return "revocationWarning (4)";
      case 5:
        return "revocationNotification (5)";
      case 6:
        return "keyUpdateWarning (6)";
      default:
        return Integer.toString(status);
    }
  } // method buildText

}
