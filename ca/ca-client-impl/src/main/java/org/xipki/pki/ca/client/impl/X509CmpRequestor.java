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

package org.xipki.pki.ca.client.impl;

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
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.CertificateConfirmationContent;
import org.bouncycastle.cert.cmp.CertificateConfirmationContentBuilder;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xipki.commons.common.RequestResponseDebug;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.common.util.XMLUtil;
import org.xipki.commons.security.api.CRLReason;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.XipkiCmpConstants;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.client.api.CertprofileInfo;
import org.xipki.pki.ca.client.api.PKIErrorException;
import org.xipki.pki.ca.client.api.dto.CRLResultType;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestEntryType;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestType;
import org.xipki.pki.ca.client.api.dto.EnrollCertResultEntryType;
import org.xipki.pki.ca.client.api.dto.EnrollCertResultType;
import org.xipki.pki.ca.client.api.dto.ErrorResultEntryType;
import org.xipki.pki.ca.client.api.dto.IssuerSerialEntryType;
import org.xipki.pki.ca.client.api.dto.P10EnrollCertRequestType;
import org.xipki.pki.ca.client.api.dto.ResultEntryType;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequestEntryType;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequestType;
import org.xipki.pki.ca.client.api.dto.RevokeCertResultEntryType;
import org.xipki.pki.ca.client.api.dto.RevokeCertResultType;
import org.xipki.pki.ca.client.api.dto.UnrevokeOrRemoveCertRequestType;
import org.xipki.pki.ca.common.cmp.CmpUtf8Pairs;
import org.xipki.pki.ca.common.cmp.CmpUtil;
import org.xipki.pki.ca.common.cmp.PKIResponse;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class X509CmpRequestor extends CmpRequestor {

  private static final DigestCalculatorProvider DIGEST_CALCULATOR_PROVIDER
      = new BcDigestCalculatorProvider();

  private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

  private static final Logger LOG = LoggerFactory.getLogger(X509CmpRequestor.class);

  private final DocumentBuilder xmlDocBuilder;

  private boolean implicitConfirm = true;

  X509CmpRequestor(
      final X509Certificate requestorCert,
      final X509Certificate responderCert,
      final SecurityFactory securityFactory) {
    super(requestorCert, responderCert, securityFactory);
    xmlDocBuilder = newDocumentBuilder();
  }

  X509CmpRequestor(
      final ConcurrentContentSigner requestor,
      final X509Certificate responderCert,
      final SecurityFactory securityFactory,
      final boolean signRequest) {
    super(requestor, responderCert, securityFactory, signRequest);
    xmlDocBuilder = newDocumentBuilder();
  }

  public CRLResultType generateCRL(
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    int action = XipkiCmpConstants.ACTION_GEN_CRL;
    PKIMessage request = buildMessageWithXipkAction(action, null);
    PKIResponse response = signAndSend(request, debug);
    return evaluateCRLResponse(response, action);
  }

  public CRLResultType downloadCurrentCRL(
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    return downloadCRL((BigInteger) null, debug);
  }

  public CRLResultType downloadCRL(
      final BigInteger crlNumber,
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    Integer action = null;
    PKIMessage request;
    if (crlNumber == null) {
      ASN1ObjectIdentifier type = CMPObjectIdentifiers.it_currentCRL;
      request = buildMessageWithGeneralMsgContent(type, null);
    } else {
      action = XipkiCmpConstants.ACTION_GET_CRL_WITH_SN;
      request = buildMessageWithXipkAction(action, new ASN1Integer(crlNumber));
    }

    PKIResponse response = signAndSend(request, debug);
    return evaluateCRLResponse(response, action);
  }

  private CRLResultType evaluateCRLResponse(
      final PKIResponse response,
      final Integer xipkiAction)
  throws CmpRequestorException, PKIErrorException {
    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
      throw new PKIErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_GEN_REP != bodyType) {
      throw new CmpRequestorException("unknown PKI body type " + bodyType
          + " instead the exceptected [" + PKIBody.TYPE_GEN_REP  + ", "
          + PKIBody.TYPE_ERROR + "]");
    }

    ASN1ObjectIdentifier expectedType = (xipkiAction == null)
        ? CMPObjectIdentifiers.it_currentCRL
        : ObjectIdentifiers.id_xipki_cm_cmpGenmsg;

    GenRepContent genRep = (GenRepContent) respBody.getContent();

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
      throw new CmpRequestorException("the response does not contain InfoTypeAndValue "
          + expectedType);
    }

    ASN1Encodable certListAsn1Object;
    if (xipkiAction == null) {
      certListAsn1Object = itv.getInfoValue();
    } else {
      certListAsn1Object = extractXipkiActionContent(itv.getInfoValue(), xipkiAction);
    }

    CertificateList certList = CertificateList.getInstance(certListAsn1Object);

    X509CRL crl;
    try {
      crl = new X509CRLObject(certList);
    } catch (CRLException ex) {
      throw new CmpRequestorException("returned CRL is invalid: " + ex.getMessage());
    }

    CRLResultType result = new CRLResultType();
    result.setCrl(crl);
    return result;
  } // method evaluateCRLResponse

  public RevokeCertResultType revokeCertificate(
      final RevokeCertRequestType request,
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    PKIMessage reqMessage = buildRevokeCertRequest(request);
    PKIResponse response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  }

  public RevokeCertResultType unrevokeCertificate(
      final UnrevokeOrRemoveCertRequestType request,
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    PKIMessage reqMessage = buildUnrevokeOrRemoveCertRequest(request,
        CRLReason.REMOVE_FROM_CRL.getCode());
    PKIResponse response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  }

  public RevokeCertResultType removeCertificate(
      final UnrevokeOrRemoveCertRequestType request,
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    PKIMessage reqMessage = buildUnrevokeOrRemoveCertRequest(request,
        XipkiCmpConstants.CRL_REASON_REMOVE);
    PKIResponse response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  }

  private RevokeCertResultType parse(
      final PKIResponse response,
      final List<? extends IssuerSerialEntryType> reqEntries)
  throws CmpRequestorException, PKIErrorException {
    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
      throw new PKIErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_REVOCATION_REP != bodyType) {
      throw new CmpRequestorException("unknown PKI body type " + bodyType
          + " instead the exceptected [" + PKIBody.TYPE_REVOCATION_REP  + ", "
          + PKIBody.TYPE_ERROR + "]");
    }

    RevRepContent content = (RevRepContent) respBody.getContent();
    PKIStatusInfo[] statuses = content.getStatus();
    if (statuses == null || statuses.length != reqEntries.size()) {
      throw new CmpRequestorException("incorrect number of status entries in response '"
          + statuses.length + "' instead the exceptected '" + reqEntries.size() + "'");
    }

    CertId[] revCerts = content.getRevCerts();

    RevokeCertResultType result = new RevokeCertResultType();
    for (int i = 0; i < statuses.length; i++) {
      PKIStatusInfo statusInfo = statuses[i];
      int status = statusInfo.getStatus().intValue();
      IssuerSerialEntryType re = reqEntries.get(i);

      if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
        PKIFreeText text = statusInfo.getStatusString();
        String statusString = (text == null)
            ? null
            : text.getStringAt(0).getString();

        ResultEntryType resultEntry = new ErrorResultEntryType(
            re.getId(), status,
            statusInfo.getFailInfo().intValue(),
            statusString);
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
            X509Util.getRFC4519Name(re.getIssuer()), re.getSerialNumber());
        certId = new CertId(new GeneralName(re.getIssuer()), re.getSerialNumber());
        continue;
      }

      ResultEntryType resultEntry = new RevokeCertResultEntryType(re.getId(), certId);
      result.addResultEntry(resultEntry);
    }

    return result;
  } // method parse

  public EnrollCertResultType requestCertificate(
      final P10EnrollCertRequestType p10Req,
      final String username,
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    PKIMessage request = buildPKIMessage(p10Req, username);
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    reqIdIdMap.put(MINUS_ONE, p10Req.getId());
    return internRequestCertificate(request, reqIdIdMap, PKIBody.TYPE_CERT_REP, debug);
  }

  public EnrollCertResultType requestCertificate(
      final EnrollCertRequestType req,
      final String username,
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    PKIMessage request = buildPKIMessage(req, username);
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    List<EnrollCertRequestEntryType> reqEntries = req.getRequestEntries();

    for (EnrollCertRequestEntryType reqEntry : reqEntries) {
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

    return internRequestCertificate(request, reqIdIdMap, exptectedBodyType, debug);
  }

  private EnrollCertResultType internRequestCertificate(
      final PKIMessage reqMessage,
      final Map<BigInteger, String> reqIdIdMap,
      final int expectedBodyType,
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    PKIResponse response = signAndSend(reqMessage, debug);
    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
      throw new PKIErrorException(content.getPKIStatusInfo());
    } else if (expectedBodyType != bodyType) {
      throw new CmpRequestorException("unknown PKI body type " + bodyType
          + " instead the exceptected [" + expectedBodyType  + ", "
          + PKIBody.TYPE_ERROR + "]");
    }

    CertRepMessage certRep = (CertRepMessage) respBody.getContent();
    CertResponse[] certResponses = certRep.getResponse();

    EnrollCertResultType result = new EnrollCertResultType();

    // CA certificates
    CMPCertificate[] caPubs = certRep.getCaPubs();
    if (caPubs != null && caPubs.length > 0) {
      for (int i = 0; i < caPubs.length; i++) {
        if (caPubs[i] != null) {
          result.addCACertificate(caPubs[i]);
        }
      }
    }

    boolean isImplicitConfirm = CmpUtil.isImplictConfirm(response.getPkiMessage().getHeader());

    CertificateConfirmationContentBuilder certConfirmBuilder = isImplicitConfirm
        ? null
        : new CertificateConfirmationContentBuilder();
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

      ResultEntryType resultEntry;
      if (status == PKIStatus.GRANTED || status == PKIStatus.GRANTED_WITH_MODS) {
        CertifiedKeyPair cvk = certResp.getCertifiedKeyPair();
        if (cvk == null) {
          return null;
        }

        CMPCertificate cmpCert = cvk.getCertOrEncCert().getCertificate();
        if (cmpCert == null) {
          return null;
        }

        resultEntry = new EnrollCertResultEntryType(thisId, cmpCert, status);

        if (!isImplicitConfirm) {
          requireConfirm = true;
          X509CertificateHolder certHolder = null;
          try {
            certHolder = new X509CertificateHolder(cmpCert.getEncoded());
          } catch (IOException ex) {
            resultEntry = new ErrorResultEntryType(thisId,
                ClientErrorCode.PKISTATUS_RESPONSE_ERROR,
                PKIFailureInfo.systemFailure,
                "error while decode the certificate");
          }

          if (certHolder != null) {
            certConfirmBuilder.addAcceptedCertificate(certHolder, certReqId);
          }
        }
      } else {
        PKIFreeText statusString = statusInfo.getStatusString();
        String errorMessage = (statusString == null)
            ? null
            : statusString.getStringAt(0).getString();
        int failureInfo = statusInfo.getFailInfo().intValue();

        resultEntry = new ErrorResultEntryType(thisId, status, failureInfo, errorMessage);
      }
      result.addResultEntry(resultEntry);
    }

    if (CollectionUtil.isNotEmpty(reqIdIdMap)) {
      for (BigInteger reqId : reqIdIdMap.keySet()) {
        ErrorResultEntryType ere = new ErrorResultEntryType(reqIdIdMap.get(reqId),
            ClientErrorCode.PKISTATUS_NO_ANSWER);
        result.addResultEntry(ere);
      }
    }

    if (!requireConfirm) {
      return result;
    }

    PKIMessage confirmRequest = buildCertConfirmRequest(
        response.getPkiMessage().getHeader().getTransactionID(),
        certConfirmBuilder);

    response = signAndSend(confirmRequest, debug);
    checkProtection(response);

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
      throw new PKIErrorException(content.getPKIStatusInfo());
    }

    return result;
  } // method intern_requestCertificate

  private PKIMessage buildCertConfirmRequest(
      final ASN1OctetString tid,
      final CertificateConfirmationContentBuilder certConfirmBuilder)
  throws CmpRequestorException {
    PKIHeader header = buildPKIHeader(implicitConfirm, tid, null, (InfoTypeAndValue[]) null);
    CertificateConfirmationContent certConfirm;
    try {
      certConfirm = certConfirmBuilder.build(DIGEST_CALCULATOR_PROVIDER);
    } catch (CMPException ex) {
      throw new CmpRequestorException(ex.getMessage(), ex);
    }
    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, certConfirm.toASN1Structure());
    return new PKIMessage(header, body);
  }

  private PKIMessage buildRevokeCertRequest(
      final RevokeCertRequestType request)
  throws CmpRequestorException {
    PKIHeader header = buildPKIHeader(null);

    List<RevokeCertRequestEntryType> requestEntries = request.getRequestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (RevokeCertRequestEntryType requestEntry : requestEntries) {
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
      certTempBuilder.setIssuer(requestEntry.getIssuer());
      certTempBuilder.setSerialNumber(new ASN1Integer(requestEntry.getSerialNumber()));

      Date invalidityDate = requestEntry.getInvalidityDate();
      int idx = (invalidityDate == null)
          ? 1
          : 2;
      Extension[] extensions = new Extension[idx];

      try {
        ASN1Enumerated reason = new ASN1Enumerated(requestEntry.getReason());
        extensions[0] = new Extension(Extension.reasonCode,
            true, new DEROctetString(reason.getEncoded()));

        if (invalidityDate != null) {
          ASN1GeneralizedTime time = new ASN1GeneralizedTime(invalidityDate);
          extensions[1] = new Extension(Extension.invalidityDate,
            true, new DEROctetString(time.getEncoded()));
        }
      } catch (IOException ex) {
        throw new CmpRequestorException(ex.getMessage(), ex);
      }
      Extensions exts = new Extensions(extensions);

      RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    PKIBody body = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content);
    return new PKIMessage(header, body);
  } // method buildRevokeCertRequest

  private PKIMessage buildUnrevokeOrRemoveCertRequest(
      final UnrevokeOrRemoveCertRequestType request,
      final int reasonCode)
  throws CmpRequestorException {
    PKIHeader header = buildPKIHeader(null);

    List<IssuerSerialEntryType> requestEntries = request.getRequestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (IssuerSerialEntryType requestEntry : requestEntries) {
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
      certTempBuilder.setIssuer(requestEntry.getIssuer());
      certTempBuilder.setSerialNumber(new ASN1Integer(requestEntry.getSerialNumber()));

      Extension[] extensions = new Extension[1];

      try {
        ASN1Enumerated reason = new ASN1Enumerated(reasonCode);
        extensions[0] = new Extension(Extension.reasonCode,
            true, new DEROctetString(reason.getEncoded()));
      } catch (IOException ex) {
        throw new CmpRequestorException(ex.getMessage(), ex);
      }
      Extensions exts = new Extensions(extensions);

      RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    PKIBody body = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content);
    return new PKIMessage(header, body);
  } // method buildUnrevokeOrRemoveCertRequest

  private PKIMessage buildPKIMessage(
      final P10EnrollCertRequestType p10Req,
      final String username) {
    CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERT_PROFILE,
        p10Req.getCertprofile());
    if (StringUtil.isNotBlank(username)) {
      utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_USER, username);
    }

    PKIHeader header = buildPKIHeader(implicitConfirm, null, utf8Pairs);
    PKIBody body = new PKIBody(PKIBody.TYPE_P10_CERT_REQ, p10Req.getP10Req());

    return new PKIMessage(header, body);
  }

  private PKIMessage buildPKIMessage(
      final EnrollCertRequestType req,
      final String username) {
    PKIHeader header = buildPKIHeader(implicitConfirm, null, username);

    List<EnrollCertRequestEntryType> reqEntries = req.getRequestEntries();
    CertReqMsg[] certReqMsgs = new CertReqMsg[reqEntries.size()];

    for (int i = 0; i < reqEntries.size(); i++) {
      EnrollCertRequestEntryType reqEntry = reqEntries.get(i);
      CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERT_PROFILE,
          reqEntry.getCertprofile());
      AttributeTypeAndValue certprofileInfo = CmpUtil.buildAttributeTypeAndValue(utf8Pairs);

      AttributeTypeAndValue[] atvs = (certprofileInfo == null)
          ? null
          : new AttributeTypeAndValue[]{certprofileInfo};
      certReqMsgs[i] = new CertReqMsg(
          reqEntry.getCertReq(), reqEntry.getPopo(),
          atvs);
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

    PKIMessage pkiMessage = new PKIMessage(header, body);
    return pkiMessage;
  } // method buildPKIMessage

  private PKIMessage buildPKIMessage(
      final CertRequest req,
      final ProofOfPossession pop,
      final String profileName,
      final String username) {
    PKIHeader header = buildPKIHeader(implicitConfirm, null, username);

    CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERT_PROFILE, profileName);
    AttributeTypeAndValue certprofileInfo = CmpUtil.buildAttributeTypeAndValue(utf8Pairs);
    CertReqMsg[] certReqMsgs = new CertReqMsg[1];
    certReqMsgs[0] = new CertReqMsg(req, pop, new AttributeTypeAndValue[]{certprofileInfo});
    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_REQ, new CertReqMessages(certReqMsgs));

    return new PKIMessage(header, body);
  }

  public PKIMessage envelope(
      final CertRequest req,
      final ProofOfPossession pop,
      final String profileName,
      final String username)
  throws CmpRequestorException {
    PKIMessage request = buildPKIMessage(req, pop, profileName, username);
    return sign(request);
  }

  public PKIMessage envelopeRevocation(
      final RevokeCertRequestType request)
  throws CmpRequestorException {
    PKIMessage reqMessage = buildRevokeCertRequest(request);
    reqMessage = sign(reqMessage);
    return reqMessage;
  }

  public CAInfo retrieveCAInfo(
      final String caName,
      final RequestResponseDebug debug)
  throws CmpRequestorException, PKIErrorException {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1Integer(2));
    ASN1Sequence acceptVersions = new DERSequence(v);

    int action = XipkiCmpConstants.ACTION_GET_CAINFO;
    PKIMessage request = buildMessageWithXipkAction(action, acceptVersions);
    PKIResponse response = signAndSend(request, debug);
    ASN1Encodable itvValue = extractXipkiActionRepContent(response, action);
    DERUTF8String utf8Str = DERUTF8String.getInstance(itvValue);
    String systemInfoStr = utf8Str.getString();

    LOG.debug("CAInfo for CA {}: {}", caName, systemInfoStr);
    Document doc;
    try {
      doc = xmlDocBuilder.parse(new ByteArrayInputStream(systemInfoStr.getBytes("UTF-8")));
    } catch (SAXException | IOException ex) {
      throw new CmpRequestorException("could not parse the returned systemInfo for CA "
          + caName + ": " + ex.getMessage(), ex);
    }

    final String namespace = null;
    Element root = doc.getDocumentElement();
    String s = root.getAttribute("version");
    if (StringUtil.isBlank(s)) {
      s = root.getAttributeNS(namespace, "version");
    }

    int version = StringUtil.isBlank(s)
        ? 1
        : Integer.parseInt(s);

    if (version == 2) {
      X509Certificate caCert;

      String b64CACert = XMLUtil.getValueOfFirstElementChild(root, namespace, "CACert");
      try {
        caCert = X509Util.parseBase64EncodedCert(b64CACert);
      } catch (CertificateException | IOException ex) {
        throw new CmpRequestorException("could no parse the CA certificate", ex);
      }

      Element profilesElement = XMLUtil.getFirstElementChild(root, namespace, "certprofiles");
      Set<CertprofileInfo> profiles = new HashSet<>();
      Set<String> profileNames = new HashSet<>();
      if (profilesElement != null) {
        List<Element> profileElements = XMLUtil.getElementChilden(
            profilesElement, namespace, "certprofile");

        for (Element element : profileElements) {
          String name = XMLUtil.getValueOfFirstElementChild(element, namespace, "name");
          String type = XMLUtil.getValueOfFirstElementChild(element, namespace, "type");
          String conf = XMLUtil.getValueOfFirstElementChild(element, namespace, "conf");
          CertprofileInfo profile = new CertprofileInfo(name, type, conf);
          profiles.add(profile);
          profileNames.add(name);
          if (LOG.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("configured for CA ").append(caName).append(" certprofile (");
            sb.append("name=").append(name).append(", ");
            sb.append("type=").append(type).append(", ");
            sb.append("conf=").append(conf).append(")");
            LOG.debug(sb.toString());
          }
        }
      }

      LOG.info("CA {} supports profiles {}", caName, profileNames);
      return new CAInfo(caCert, profiles);
    } else {
      throw new CmpRequestorException("unknown CAInfo version " + version);
    }
  } // method retrieveCAInfo

  private static DocumentBuilder newDocumentBuilder() {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    try {
      return dbf.newDocumentBuilder();
    } catch (ParserConfigurationException ex) {
      throw new RuntimeException("could not create XML document builder", ex);
    }
  }

}
