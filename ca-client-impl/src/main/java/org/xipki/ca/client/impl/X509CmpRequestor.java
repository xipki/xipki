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

package org.xipki.ca.client.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
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
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.CertificateConfirmationContent;
import org.bouncycastle.cert.cmp.CertificateConfirmationContentBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xipki.ca.client.api.CaClientException;
import org.xipki.ca.client.api.CertprofileInfo;
import org.xipki.ca.client.api.PkiErrorException;
import org.xipki.ca.client.api.dto.CsrEnrollCertRequest;
import org.xipki.ca.client.api.dto.EnrollCertRequest;
import org.xipki.ca.client.api.dto.EnrollCertRequestEntry;
import org.xipki.ca.client.api.dto.EnrollCertResultEntry;
import org.xipki.ca.client.api.dto.EnrollCertResultResp;
import org.xipki.ca.client.api.dto.ErrorResultEntry;
import org.xipki.ca.client.api.dto.IssuerSerialEntry;
import org.xipki.ca.client.api.dto.ResultEntry;
import org.xipki.ca.client.api.dto.RevokeCertRequest;
import org.xipki.ca.client.api.dto.RevokeCertRequestEntry;
import org.xipki.ca.client.api.dto.RevokeCertResultEntry;
import org.xipki.ca.client.api.dto.RevokeCertResultType;
import org.xipki.ca.client.api.dto.UnrevokeOrRemoveCertEntry;
import org.xipki.ca.client.api.dto.UnrevokeOrRemoveCertRequest;
import org.xipki.cmp.CmpUtf8Pairs;
import org.xipki.cmp.CmpUtil;
import org.xipki.cmp.PkiResponse;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.CrlReason;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.XiSecurityConstants;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.DateUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.RequestResponseDebug;
import org.xipki.util.StringUtil;
import org.xipki.util.XmlUtil;
import org.xml.sax.SAXException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class X509CmpRequestor extends CmpRequestor {

  private static final DigestCalculatorProvider DIGEST_CALCULATOR_PROVIDER =
      new BcDigestCalculatorProvider();

  private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

  private static final Logger LOG = LoggerFactory.getLogger(X509CmpRequestor.class);

  private final DocumentBuilder xmlDocBuilder;

  private boolean implicitConfirm = true;

  X509CmpRequestor(X509Certificate requestorCert, CmpResponder responder,
      SecurityFactory securityFactory) {
    super(requestorCert, responder, securityFactory);
    xmlDocBuilder = newDocumentBuilder();
  }

  X509CmpRequestor(ConcurrentContentSigner requestor, CmpResponder responder,
      SecurityFactory securityFactory) {
    super(requestor, responder, securityFactory);
    xmlDocBuilder = newDocumentBuilder();
  }

  public X509CRL generateCrl(RequestResponseDebug debug)
      throws CaClientException, PkiErrorException {
    int action = XiSecurityConstants.CMP_ACTION_GEN_CRL;
    PKIMessage request = buildMessageWithXipkAction(action, null);
    PkiResponse response = signAndSend(request, debug);
    return evaluateCrlResponse(response, action);
  }

  public X509CRL downloadCurrentCrl(RequestResponseDebug debug)
      throws CaClientException, PkiErrorException {
    return downloadCrl((BigInteger) null, debug);
  }

  public X509CRL downloadCrl(BigInteger crlNumber, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException {
    Integer action = null;
    PKIMessage request;
    if (crlNumber == null) {
      ASN1ObjectIdentifier type = CMPObjectIdentifiers.it_currentCRL;
      request = buildMessageWithGeneralMsgContent(type, null);
    } else {
      action = XiSecurityConstants.CMP_ACTION_GET_CRL_WITH_SN;
      request = buildMessageWithXipkAction(action, new ASN1Integer(crlNumber));
    }

    PkiResponse response = signAndSend(request, debug);
    return evaluateCrlResponse(response, action);
  }

  private X509CRL evaluateCrlResponse(PkiResponse response, Integer xipkiAction)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);

    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_GEN_REP != bodyType) {
      throw new CaClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, PKIBody.TYPE_GEN_REP, PKIBody.TYPE_ERROR));
    }

    ASN1ObjectIdentifier expectedType = (xipkiAction == null)
        ? CMPObjectIdentifiers.it_currentCRL : ObjectIdentifiers.id_xipki_cmp_cmpGenmsg;

    GenRepContent genRep = GenRepContent.getInstance(respBody.getContent());

    InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
    InfoTypeAndValue itv = null;
    if (itvs != null && itvs.length > 0) {
      for (InfoTypeAndValue m : itvs) {
        if (expectedType.equals(m.getInfoType())) {
          itv = m;
          break;
        }
      }
    }

    if (itv == null) {
      throw new CaClientException("the response does not contain InfoTypeAndValue "
          + expectedType);
    }

    ASN1Encodable certListAsn1Object = (xipkiAction == null) ? itv.getInfoValue()
        : extractXiActionContent(itv.getInfoValue(), xipkiAction);

    CertificateList certList = CertificateList.getInstance(certListAsn1Object);

    X509CRL crl;
    try {
      crl = X509Util.toX509Crl(certList);
    } catch (CRLException | CertificateException ex) {
      throw new CaClientException("returned CRL is invalid: " + ex.getMessage());
    }

    return crl;
  } // method evaluateCrlResponse

  public RevokeCertResultType revokeCertificate(RevokeCertRequest request,
      RequestResponseDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    PKIMessage reqMessage = buildRevokeCertRequest(request);
    PkiResponse response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  }

  public RevokeCertResultType unrevokeCertificate(UnrevokeOrRemoveCertRequest request,
      RequestResponseDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    PKIMessage reqMessage = buildUnrevokeOrRemoveCertRequest(request,
        CrlReason.REMOVE_FROM_CRL.getCode());
    PkiResponse response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  }

  public RevokeCertResultType removeCertificate(UnrevokeOrRemoveCertRequest request,
      RequestResponseDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    PKIMessage reqMessage = buildUnrevokeOrRemoveCertRequest(request,
            XiSecurityConstants.CMP_CRL_REASON_REMOVE);
    PkiResponse response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  }

  private RevokeCertResultType parse(PkiResponse response,
      List<? extends IssuerSerialEntry> reqEntries) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);

    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_REVOCATION_REP != bodyType) {
      throw new CaClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
          PKIBody.TYPE_REVOCATION_REP, PKIBody.TYPE_ERROR));
    }

    RevRepContent content = RevRepContent.getInstance(respBody.getContent());
    PKIStatusInfo[] statuses = content.getStatus();
    if (statuses == null || statuses.length != reqEntries.size()) {
      int statusesLen = 0;
      if (statuses != null) {
        statusesLen = statuses.length;
      }

      throw new CaClientException(String.format(
          "incorrect number of status entries in response '%s' instead the expected '%s'",
          statusesLen, reqEntries.size()));
    }

    CertId[] revCerts = content.getRevCerts();

    RevokeCertResultType result = new RevokeCertResultType();
    for (int i = 0; i < statuses.length; i++) {
      PKIStatusInfo statusInfo = statuses[i];
      int status = statusInfo.getStatus().intValue();
      IssuerSerialEntry re = reqEntries.get(i);

      if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
        PKIFreeText text = statusInfo.getStatusString();
        String statusString = (text == null) ? null : text.getStringAt(0).getString();

        ResultEntry resultEntry = new ErrorResultEntry(re.getId(), status,
            statusInfo.getFailInfo().intValue(), statusString);
        result.addResultEntry(resultEntry);
        continue;
      }

      CertId certId = null;
      if (revCerts != null) {
        for (CertId entry : revCerts) {
          if (re.getIssuer().equals(entry.getIssuer().getName())
              && re.getSerialNumber().equals(entry.getSerialNumber().getValue())) {
            certId = entry;
            break;
          }
        }
      }

      if (certId == null) {
        LOG.warn("certId is not present in response for (issuer='{}', serialNumber={})",
            X509Util.getRfc4519Name(re.getIssuer()), LogUtil.formatCsn(re.getSerialNumber()));
        certId = new CertId(new GeneralName(re.getIssuer()), re.getSerialNumber());
        continue;
      }

      ResultEntry resultEntry = new RevokeCertResultEntry(re.getId(), certId);
      result.addResultEntry(resultEntry);
    }

    return result;
  } // method parse

  public EnrollCertResultResp requestCertificate(CsrEnrollCertRequest csr, Date notBefore,
      Date notAfter, RequestResponseDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("csr", csr);

    PKIMessage request = buildPkiMessage(csr, notBefore, notAfter);
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    reqIdIdMap.put(MINUS_ONE, csr.getId());
    return requestCertificate0(request, reqIdIdMap, PKIBody.TYPE_CERT_REP, debug);
  }

  public EnrollCertResultResp requestCertificate(EnrollCertRequest req, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("req", req);

    PKIMessage request = buildPkiMessage(req);
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    List<EnrollCertRequestEntry> reqEntries = req.getRequestEntries();

    for (EnrollCertRequestEntry reqEntry : reqEntries) {
      reqIdIdMap.put(reqEntry.getCertReq().getCertReqId().getValue(), reqEntry.getId());
    }

    int exptectedBodyType;
    switch (req.getType()) {
      case CERT_REQ:
        exptectedBodyType = PKIBody.TYPE_CERT_REP;
        break;
      case KEY_UPDATE:
        exptectedBodyType = PKIBody.TYPE_KEY_UPDATE_REP;
        break;
      default:
        exptectedBodyType = PKIBody.TYPE_CROSS_CERT_REP;
    }

    return requestCertificate0(request, reqIdIdMap, exptectedBodyType, debug);
  }

  private EnrollCertResultResp requestCertificate0(PKIMessage reqMessage,
      Map<BigInteger, String> reqIdIdMap, int expectedBodyType, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException {
    PkiResponse response = signAndSend(reqMessage, debug);
    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    final int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (expectedBodyType != bodyType) {
      throw new CaClientException(String.format(
              "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
              expectedBodyType, PKIBody.TYPE_ERROR));
    }

    CertRepMessage certRep = CertRepMessage.getInstance(respBody.getContent());
    CertResponse[] certResponses = certRep.getResponse();

    EnrollCertResultResp result = new EnrollCertResultResp();

    // CA certificates
    CMPCertificate[] caPubs = certRep.getCaPubs();
    if (caPubs != null && caPubs.length > 0) {
      for (int i = 0; i < caPubs.length; i++) {
        if (caPubs[i] != null) {
          result.addCaCertificate(caPubs[i]);
        }
      }
    }

    CertificateConfirmationContentBuilder certConfirmBuilder = null;
    if (!CmpUtil.isImplictConfirm(response.getPkiMessage().getHeader())) {
      certConfirmBuilder = new CertificateConfirmationContentBuilder();
    }
    boolean requireConfirm = false;

    // We only accept the certificates which are requested.
    for (CertResponse certResp : certResponses) {
      PKIStatusInfo statusInfo = certResp.getStatus();
      int status = statusInfo.getStatus().intValue();
      BigInteger certReqId = certResp.getCertReqId().getValue();
      String thisId = reqIdIdMap.get(certReqId);
      if (thisId != null) {
        reqIdIdMap.remove(certReqId);
      } else if (reqIdIdMap.size() == 1) {
        thisId = reqIdIdMap.values().iterator().next();
        reqIdIdMap.clear();
      }

      if (thisId == null) {
        continue; // ignore it. this cert is not requested by me
      }

      ResultEntry resultEntry;
      if (status == PKIStatus.GRANTED || status == PKIStatus.GRANTED_WITH_MODS) {
        CertifiedKeyPair cvk = certResp.getCertifiedKeyPair();
        if (cvk == null) {
          return null;
        }

        CMPCertificate cmpCert = cvk.getCertOrEncCert().getCertificate();
        if (cmpCert == null) {
          return null;
        }

        PrivateKeyInfo privKeyInfo = null;
        if (cvk.getPrivateKey() != null) {
          byte[] decryptedValue;
          try {
            decryptedValue = decrypt(cvk.getPrivateKey());
          } catch (XiSecurityException ex) {
            resultEntry = new ErrorResultEntry(thisId, ClientErrorCode.PKISTATUS_RESPONSE_ERROR,
                PKIFailureInfo.systemFailure, "could not decrypt PrivateKeyInfo");
            continue;
          }
          privKeyInfo = PrivateKeyInfo.getInstance(decryptedValue);
        }

        resultEntry = new EnrollCertResultEntry(thisId, cmpCert, privKeyInfo, status);

        if (certConfirmBuilder != null) {
          requireConfirm = true;
          X509CertificateHolder certHolder = null;
          try {
            certHolder = new X509CertificateHolder(cmpCert.getEncoded());
          } catch (IOException ex) {
            resultEntry = new ErrorResultEntry(thisId, ClientErrorCode.PKISTATUS_RESPONSE_ERROR,
                PKIFailureInfo.systemFailure, "could not decode the certificate");
          }

          if (certHolder != null) {
            certConfirmBuilder.addAcceptedCertificate(certHolder, certReqId);
          }
        }
      } else {
        PKIFreeText statusString = statusInfo.getStatusString();
        String errorMessage = (statusString == null)
            ? null : statusString.getStringAt(0).getString();
        int failureInfo = statusInfo.getFailInfo().intValue();

        resultEntry = new ErrorResultEntry(thisId, status, failureInfo, errorMessage);
      }
      result.addResultEntry(resultEntry);
    }

    if (CollectionUtil.isNonEmpty(reqIdIdMap)) {
      for (BigInteger reqId : reqIdIdMap.keySet()) {
        ErrorResultEntry ere =
            new ErrorResultEntry(reqIdIdMap.get(reqId), ClientErrorCode.PKISTATUS_NO_ANSWER);
        result.addResultEntry(ere);
      }
    }

    if (!requireConfirm) {
      return result;
    }

    PKIMessage confirmRequest = buildCertConfirmRequest(
        response.getPkiMessage().getHeader().getTransactionID(), certConfirmBuilder);

    response = signAndSend(confirmRequest, debug);
    checkProtection(response);

    return result;
  } // method requestCertificate0

  private PKIMessage buildCertConfirmRequest(ASN1OctetString tid,
      CertificateConfirmationContentBuilder certConfirmBuilder) throws CaClientException {
    PKIHeader header = buildPkiHeader(implicitConfirm, tid, null, (InfoTypeAndValue[]) null);
    CertificateConfirmationContent certConfirm;
    try {
      certConfirm = certConfirmBuilder.build(DIGEST_CALCULATOR_PROVIDER);
    } catch (CMPException ex) {
      throw new CaClientException(ex.getMessage(), ex);
    }
    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, certConfirm.toASN1Structure());
    return new PKIMessage(header, body);
  }

  private PKIMessage buildRevokeCertRequest(RevokeCertRequest request)
      throws CaClientException {
    PKIHeader header = buildPkiHeader(null);

    List<RevokeCertRequestEntry> requestEntries = request.getRequestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (RevokeCertRequestEntry requestEntry : requestEntries) {
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
      certTempBuilder.setIssuer(requestEntry.getIssuer());
      certTempBuilder.setSerialNumber(new ASN1Integer(requestEntry.getSerialNumber()));
      byte[] aki = requestEntry.getAuthorityKeyIdentifier();
      if (aki != null) {
        Extensions certTempExts = getCertTempExtensions(aki);
        certTempBuilder.setExtensions(certTempExts);
      }

      Date invalidityDate = requestEntry.getInvalidityDate();
      int idx = (invalidityDate == null) ? 1 : 2;
      Extension[] extensions = new Extension[idx];

      try {
        ASN1Enumerated reason = new ASN1Enumerated(requestEntry.getReason());
        extensions[0] = new Extension(Extension.reasonCode, true,
            new DEROctetString(reason.getEncoded()));

        if (invalidityDate != null) {
          ASN1GeneralizedTime time = new ASN1GeneralizedTime(invalidityDate);
          extensions[1] = new Extension(Extension.invalidityDate, true,
                  new DEROctetString(time.getEncoded()));
        }
      } catch (IOException ex) {
        throw new CaClientException(ex.getMessage(), ex);
      }

      Extensions exts = new Extensions(extensions);

      RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    PKIBody body = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content);
    return new PKIMessage(header, body);
  } // method buildRevokeCertRequest

  private PKIMessage buildUnrevokeOrRemoveCertRequest(UnrevokeOrRemoveCertRequest request,
      int reasonCode) throws CaClientException {
    PKIHeader header = buildPkiHeader(null);

    List<UnrevokeOrRemoveCertEntry> requestEntries = request.getRequestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (UnrevokeOrRemoveCertEntry requestEntry : requestEntries) {
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
      certTempBuilder.setIssuer(requestEntry.getIssuer());
      certTempBuilder.setSerialNumber(new ASN1Integer(requestEntry.getSerialNumber()));
      byte[] aki = requestEntry.getAuthorityKeyIdentifier();
      if (aki != null) {
        Extensions certTempExts = getCertTempExtensions(aki);
        certTempBuilder.setExtensions(certTempExts);
      }

      Extension[] extensions = new Extension[1];

      try {
        ASN1Enumerated reason = new ASN1Enumerated(reasonCode);
        extensions[0] = new Extension(Extension.reasonCode, true,
                new DEROctetString(reason.getEncoded()));
      } catch (IOException ex) {
        throw new CaClientException(ex.getMessage(), ex);
      }
      Extensions exts = new Extensions(extensions);

      RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    PKIBody body = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content);
    return new PKIMessage(header, body);
  } // method buildUnrevokeOrRemoveCertRequest

  private PKIMessage buildPkiMessage(CsrEnrollCertRequest csr, Date notBefore, Date notAfter) {
    CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERTPROFILE, csr.getCertprofile());

    if (notBefore != null) {
      utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_NOTBEFORE,
          DateUtil.toUtcTimeyyyyMMddhhmmss(notBefore));
    }

    if (notAfter != null) {
      utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_NOTAFTER, DateUtil.toUtcTimeyyyyMMddhhmmss(notAfter));
    }

    PKIHeader header = buildPkiHeader(implicitConfirm, null, utf8Pairs);
    PKIBody body = new PKIBody(PKIBody.TYPE_P10_CERT_REQ, csr.getCsr());

    return new PKIMessage(header, body);
  }

  private PKIMessage buildPkiMessage(EnrollCertRequest req) {
    PKIHeader header = buildPkiHeader(implicitConfirm, null);

    List<EnrollCertRequestEntry> reqEntries = req.getRequestEntries();
    CertReqMsg[] certReqMsgs = new CertReqMsg[reqEntries.size()];

    for (int i = 0; i < reqEntries.size(); i++) {
      EnrollCertRequestEntry reqEntry = reqEntries.get(i);
      CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERTPROFILE,
          reqEntry.getCertprofile());
      String genKeyType = reqEntry.getGenKeyType();
      if (genKeyType != null) {
        utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_GENERATEKEY, genKeyType);
      }

      AttributeTypeAndValue atv = CmpUtil.buildAttributeTypeAndValue(utf8Pairs);

      AttributeTypeAndValue[] atvs = new AttributeTypeAndValue[]{atv};
      certReqMsgs[i] = new CertReqMsg(reqEntry.getCertReq(), reqEntry.getPopo(), atvs);
    }

    int bodyType;
    switch (req.getType()) {
      case CERT_REQ:
        bodyType = PKIBody.TYPE_CERT_REQ;
        break;
      case KEY_UPDATE:
        bodyType = PKIBody.TYPE_KEY_UPDATE_REQ;
        break;
      default:
        bodyType = PKIBody.TYPE_CROSS_CERT_REQ;
    }

    PKIBody body = new PKIBody(bodyType, new CertReqMessages(certReqMsgs));
    return new PKIMessage(header, body);
  } // method buildPkiMessage

  private PKIMessage buildPkiMessage(CertRequest req, ProofOfPossession pop, String profileName) {
    PKIHeader header = buildPkiHeader(implicitConfirm, null);

    CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERTPROFILE, profileName);
    AttributeTypeAndValue certprofileInfo = CmpUtil.buildAttributeTypeAndValue(utf8Pairs);
    CertReqMsg[] certReqMsgs = new CertReqMsg[1];
    certReqMsgs[0] = new CertReqMsg(req, pop, new AttributeTypeAndValue[]{certprofileInfo});

    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_REQ, new CertReqMessages(certReqMsgs));
    return new PKIMessage(header, body);
  }

  public PKIMessage envelope(CertRequest req, ProofOfPossession pop, String profileName)
      throws CaClientException {
    ParamUtil.requireNonNull("req", req);
    ParamUtil.requireNonNull("pop", pop);
    ParamUtil.requireNonNull("profileName", profileName);

    PKIMessage request = buildPkiMessage(req, pop, profileName);
    return sign(request);
  }

  public PKIMessage envelopeRevocation(RevokeCertRequest request) throws CaClientException {
    ParamUtil.requireNonNull("request", request);

    PKIMessage reqMessage = buildRevokeCertRequest(request);
    reqMessage = sign(reqMessage);
    return reqMessage;
  }

  public CaInfo retrieveCaInfo(String caName, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonBlank("caName", caName);

    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1Integer(2));
    ASN1Sequence acceptVersions = new DERSequence(vec);

    int action = XiSecurityConstants.CMP_ACTION_GET_CAINFO;
    PKIMessage request = buildMessageWithXipkAction(action, acceptVersions);
    PkiResponse response = signAndSend(request, debug);
    ASN1Encodable itvValue = extractXipkiActionRepContent(response, action);
    DERUTF8String utf8Str = DERUTF8String.getInstance(itvValue);
    String systemInfoStr = utf8Str.getString();

    LOG.debug("CAInfo for CA {}: {}", caName, systemInfoStr);
    Document doc;
    try {
      doc = xmlDocBuilder.parse(new ByteArrayInputStream(systemInfoStr.getBytes("UTF-8")));
    } catch (SAXException | IOException ex) {
      throw new CaClientException("could not parse the returned systemInfo for CA "
          + caName + ": " + ex.getMessage(), ex);
    }

    final String namespace = null;
    Element root = doc.getDocumentElement();
    String str = root.getAttribute("version");
    if (StringUtil.isBlank(str)) {
      str = root.getAttributeNS(namespace, "version");
    }

    int version = StringUtil.isBlank(str) ? 1 : Integer.parseInt(str);

    if (version == 2) {
      // CACert
      X509Certificate caCert;
      String b64CaCert = XmlUtil.getValueOfFirstElementChild(root, namespace, "CACert");
      try {
        caCert = X509Util.parseBase64EncodedCert(b64CaCert);
      } catch (CertificateException ex) {
        throw new CaClientException("could no parse the CA certificate", ex);
      }

      // CmpControl
      ClientCmpControl cmpControl = null;
      Element cmpCtrlElement = XmlUtil.getFirstElementChild(root, namespace, "cmpControl");
      if (cmpCtrlElement != null) {
        String tmpStr = XmlUtil.getValueOfFirstElementChild(cmpCtrlElement, namespace,
            "rrAkiRequired");
        boolean required = (tmpStr == null) ? false : Boolean.parseBoolean(tmpStr);
        cmpControl = new ClientCmpControl(required);
      }

      // certprofiles
      Set<String> profileNames = new HashSet<>();
      Element profilesElement = XmlUtil.getFirstElementChild(root, namespace, "certprofiles");
      Set<CertprofileInfo> profiles = new HashSet<>();
      if (profilesElement != null) {
        List<Element> profileElements = XmlUtil.getElementChilden(profilesElement, namespace,
            "certprofile");

        for (Element element : profileElements) {
          String name = XmlUtil.getValueOfFirstElementChild(element, namespace, "name");
          String type = XmlUtil.getValueOfFirstElementChild(element, namespace, "type");
          String conf = XmlUtil.getValueOfFirstElementChild(element, namespace, "conf");
          CertprofileInfo profile = new CertprofileInfo(name, type, conf);
          profiles.add(profile);
          profileNames.add(name);
          LOG.debug("configured for CA {} certprofile (name={}, type={}, conf={})", caName, name,
              type, conf);
        }
      }

      LOG.info("CA {} supports profiles {}", caName, profileNames);
      return new CaInfo(caCert, cmpControl, profiles);
    } else {
      throw new CaClientException("unknown CAInfo version " + version);
    }
  } // method retrieveCaInfo

  private static DocumentBuilder newDocumentBuilder() {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    try {
      return dbf.newDocumentBuilder();
    } catch (ParserConfigurationException ex) {
      throw new RuntimeException("could not create XML document builder", ex);
    }
  }

  private static Extensions getCertTempExtensions(byte[] authorityKeyIdentifier)
      throws CaClientException {
    AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(authorityKeyIdentifier);
    byte[] encodedAki;
    try {
      encodedAki = aki.getEncoded();
    } catch (IOException ex) {
      throw new CaClientException("could not encoded AuthorityKeyIdentifier", ex);
    }
    Extension extAki = new Extension(Extension.authorityKeyIdentifier, false, encodedAki);
    Extensions certTempExts = new Extensions(extAki);
    return certTempExts;
  }

}
