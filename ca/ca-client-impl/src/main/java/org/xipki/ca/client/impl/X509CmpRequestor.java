/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.client.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEREnumerated;
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
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.CertificateConfirmationContent;
import org.bouncycastle.cert.cmp.CertificateConfirmationContentBuilder;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.cmp.CmpUtil;
import org.xipki.ca.cmp.client.ClientErrorCode;
import org.xipki.ca.cmp.client.CmpRequestor;
import org.xipki.ca.cmp.client.CmpRequestorException;
import org.xipki.ca.cmp.client.type.CRLResultType;
import org.xipki.ca.cmp.client.type.CmpResultType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType;
import org.xipki.ca.cmp.client.type.EnrollCertResultEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertResultType;
import org.xipki.ca.cmp.client.type.ErrorResultEntryType;
import org.xipki.ca.cmp.client.type.ErrorResultType;
import org.xipki.ca.cmp.client.type.P10EnrollCertRequestType;
import org.xipki.ca.cmp.client.type.ResultEntryType;
import org.xipki.ca.cmp.client.type.RevocateCertRequestEntryType;
import org.xipki.ca.cmp.client.type.RevocateCertRequestType;
import org.xipki.ca.cmp.client.type.RevocateCertResultEntryType;
import org.xipki.ca.cmp.client.type.RevocateCertResultType;
import org.xipki.ca.cmp.server.PKIResponse;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.CustomObjectIdentifiers;
import org.xipki.security.common.ParamChecker;

abstract class X509CmpRequestor extends CmpRequestor
{
    private final static DigestCalculatorProvider digesetCalculatorProvider =
            new BcDigestCalculatorProvider();
    private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

    private static final Logger LOG = LoggerFactory.getLogger(X509CmpRequestor.class);

    private boolean implicitConfirm = true;
    private final X509Certificate caCert;

    X509CmpRequestor(
            ConcurrentContentSigner requestor,
            X509Certificate responderCert,
            X509Certificate caCert,
            SecurityFactory securityFactory)
    {
        super(requestor, responderCert, securityFactory);
        ParamChecker.assertNotNull("caCert", caCert);
        this.caCert = caCert;
    }

    protected abstract byte[] send(byte[] request)
    throws IOException;

    public X509Certificate getCaCert()
    {
        return caCert;
    }

    public CmpResultType generateCRL()
    throws CmpRequestorException
    {
        ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(CustomObjectIdentifiers.id_cmp_generateCRL);
        PKIMessage request = buildMessageWithGeneralMsgContent(type);
        PKIResponse response = signAndSend(request);
        return evaluateCRLResponse(response, type);
    }

    public CmpResultType downloadCurrentCRL()
    throws CmpRequestorException
    {
        ASN1ObjectIdentifier type = CMPObjectIdentifiers.it_currentCRL;
        PKIMessage request = buildMessageWithGeneralMsgContent(type);
        PKIResponse response = signAndSend(request);
        return evaluateCRLResponse(response, type);
    }

    private CmpResultType evaluateCRLResponse(PKIResponse response, ASN1ObjectIdentifier exepectedType)
    throws CmpRequestorException
    {
        ErrorResultType errorResult = checkAndBuildErrorResultIfRequired(response);
        if(errorResult != null)
        {
            return errorResult;
        }

        PKIBody respBody = response.getPkiMessage().getBody();
        int bodyType = respBody.getType();

        if(PKIBody.TYPE_ERROR == bodyType)
        {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            return buildErrorResult(content);
        }
        else if(PKIBody.TYPE_GEN_REP != bodyType)
        {
            throw new CmpRequestorException("Unknown PKI body type " + bodyType +
                    " instead the exceptected [" + PKIBody.TYPE_GEN_REP  + ", " +
                    PKIBody.TYPE_ERROR + "]");
        }

        GenRepContent genRep = (GenRepContent) respBody.getContent();

        InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
        InfoTypeAndValue itvCurrentCRL = null;
        if(itvs != null && itvs.length > 0)
        {
            for(InfoTypeAndValue itv : itvs)
            {
                if(exepectedType.equals(itv.getInfoType()))
                {
                    itvCurrentCRL = itv;
                    break;
                }
            }
        }
        if(itvCurrentCRL == null)
        {
            throw new CmpRequestorException("The response does not contain InfoTypeAndValue currentCRL "
                    + exepectedType);
        }

        CertificateList certList = CertificateList.getInstance(itvCurrentCRL.getInfoValue());

        X509CRL crl;
        try
        {
            crl = new X509CRLObject(certList);
        } catch (CRLException e)
        {
            throw new CmpRequestorException("Returned CRL is invalid: " + e.getMessage());
        }

        CRLResultType result = new CRLResultType();
        result.setCRL(crl);
        return result;
    }

    public CmpResultType revocateCertificate(RevocateCertRequestType request)
    throws CmpRequestorException
    {
        PKIMessage reqMessage = buildRevocateCertRequest(request);
        PKIResponse response = signAndSend(reqMessage);

        ErrorResultType errorResult = checkAndBuildErrorResultIfRequired(response);
        if(errorResult != null)
        {
            return errorResult;
        }

        PKIBody respBody = response.getPkiMessage().getBody();
        int bodyType = respBody.getType();

        if(PKIBody.TYPE_ERROR == bodyType)
        {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            return buildErrorResult(content);
        }
        else if(PKIBody.TYPE_REVOCATION_REP != bodyType)
        {
            throw new CmpRequestorException("Unknown PKI body type " + bodyType +
                    " instead the exceptected [" + PKIBody.TYPE_REVOCATION_REP  + ", " +
                    PKIBody.TYPE_ERROR + "]");
        }

        RevRepContent content = (RevRepContent) respBody.getContent();
        PKIStatusInfo[] statuses = content.getStatus();
        CertId[] revCerts = content.getRevCerts();
        if(revCerts != null && statuses.length < revCerts.length)
        {
            LOG.warn("Status.length (" + statuses.length + ") < " + "RevCerts.length (" + revCerts.length + "), ignore the revCerts");
        }

        List<RevocateCertRequestEntryType> requestEntries = new ArrayList<RevocateCertRequestEntryType>(
                request.getRequestEntries());

        RevocateCertResultType result = new RevocateCertResultType();
        for(int i = 0; i < statuses.length; i++)
        {
            CertId certId = null;
            if(i < revCerts.length)
            {
                certId = revCerts[i];
            }

            RevocateCertRequestEntryType requestEntry = null;
            // find the id
            for(RevocateCertRequestEntryType re : requestEntries)
            {
                if(re.getIssuer().equals(certId.getIssuer().getName()) &&
                  re.getSerialNumber().equals(certId.getSerialNumber().getValue()))
                {
                    requestEntry = re;
                    break;
                }
            }

            if(requestEntry == null)
            {
                LOG.error("The revocated cert (issuer={}, serial={}] is not requested", certId.getIssuer().getName(),
                        certId.getSerialNumber().getValue());
                continue;
            }

            requestEntries.remove(requestEntry);
            String id = requestEntry.getId();

            PKIStatusInfo statusInfo = statuses[i];

            int status = statusInfo.getStatus().intValue();

            ResultEntryType resultEntry;
            if(status == PKIStatus.GRANTED || status == PKIStatus.GRANTED_WITH_MODS)
            {
                resultEntry = new RevocateCertResultEntryType(id, certId);
            }
            else
            {
                PKIFreeText text = statusInfo.getStatusString();
                String statusString = text == null ? null : text.getStringAt(0).getString();
                resultEntry = new ErrorResultEntryType(id, status,
                        statusInfo.getFailInfo().intValue(),
                        statusString);
            }

            result.addResultEntry(resultEntry);
        }

        if(requestEntries.isEmpty() == false)
        {
            for(RevocateCertRequestEntryType re : requestEntries)
            {
                ErrorResultEntryType ere = new ErrorResultEntryType(re.getId(), ClientErrorCode.PKIStatus_NO_ANSWER);
                result.addResultEntry(ere);
            }
        }

        return result;
    }

    public CmpResultType requestCertificate(P10EnrollCertRequestType p10Req)
    throws CmpRequestorException
    {
        PKIMessage request = buildPKIMessage(p10Req);
        Map<BigInteger, String> reqIdIdMap = new HashMap<BigInteger, String>();
        reqIdIdMap.put(MINUS_ONE, p10Req.getId());
        return intern_requestCertificate(request, reqIdIdMap, PKIBody.TYPE_CERT_REP);
    }

    public CmpResultType requestCertificate(CertReqMsg req, String extCertReqId)
    throws CmpRequestorException
    {
        PKIMessage request = buildPKIMessage(req);
        Map<BigInteger, String> reqIdIdMap = new HashMap<BigInteger, String>();

        reqIdIdMap.put(req.getCertReq().getCertReqId().getValue(), extCertReqId);

        int exptectedBodyType = PKIBody.TYPE_CERT_REP;

        return intern_requestCertificate(request, reqIdIdMap, exptectedBodyType);
    }

    public CmpResultType requestCertificate(EnrollCertRequestType req)
    throws CmpRequestorException
    {
        PKIMessage request = buildPKIMessage(req);
        Map<BigInteger, String> reqIdIdMap = new HashMap<BigInteger, String>();
        List<EnrollCertRequestEntryType> reqEntries = req.getRequestEntries();

        for(EnrollCertRequestEntryType reqEntry : reqEntries)
        {
            reqIdIdMap.put(reqEntry.getCertReq().getCertReqId().getValue(),    reqEntry.getId());
        }

        int exptectedBodyType;
        switch(req.getType())
        {
        case CERT_REQ:
            exptectedBodyType = PKIBody.TYPE_CERT_REP;
            break;
        case KEY_UPDATE:
            exptectedBodyType = PKIBody.TYPE_KEY_UPDATE_REP;
            break;
        default:
            exptectedBodyType = PKIBody.TYPE_CROSS_CERT_REP;
        }

        return intern_requestCertificate(request, reqIdIdMap, exptectedBodyType);
    }

    private CmpResultType intern_requestCertificate(
            PKIMessage reqMessage, Map<BigInteger, String> reqIdIdMap, int expectedBodyType)
    throws CmpRequestorException
    {
        PKIResponse response = signAndSend(reqMessage);

        ErrorResultType errorResult = checkAndBuildErrorResultIfRequired(response);
        if(errorResult != null)
        {
            return errorResult;
        }

        PKIBody respBody = response.getPkiMessage().getBody();
        int bodyType = respBody.getType();

        if(PKIBody.TYPE_ERROR == bodyType)
        {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            return buildErrorResult(content);
        }

        else if(expectedBodyType != bodyType)
        {
            throw new CmpRequestorException("Unknown PKI body type " + bodyType +
                    " instead the exceptected [" + expectedBodyType  + ", " +
                    PKIBody.TYPE_ERROR + "]");
        }

        CertRepMessage certRep = (CertRepMessage) respBody.getContent();
        CertResponse[] certResponses = certRep.getResponse();

        EnrollCertResultType result = new EnrollCertResultType();

        // CA certificates
        CMPCertificate[] caPubs = certRep.getCaPubs();
        if(caPubs != null && caPubs.length > 0)
        {
            for(int i = 0; i < caPubs.length; i++)
            {
                if(caPubs[i] != null)
                {
                    result.addCACertificate(caPubs[i]);
                }
            }
        }

        boolean isImplicitConfirm = CmpUtil.isImplictConfirm(response.getPkiMessage().getHeader());

        CertificateConfirmationContentBuilder certConfirmBuilder = isImplicitConfirm ?
                null : new CertificateConfirmationContentBuilder();
        boolean requireConfirm = false;

        // We only accept the certificates which are requested.
        for(CertResponse certResp : certResponses)
        {
            PKIStatusInfo statusInfo = certResp.getStatus();
            int status = statusInfo.getStatus().intValue();
            BigInteger certReqId = certResp.getCertReqId().getValue();
            String thisId = reqIdIdMap.get(certReqId);
            if(thisId != null)
            {
                reqIdIdMap.remove(certReqId);
            }
            else if(reqIdIdMap.size() == 1)
            {
                thisId = reqIdIdMap.values().iterator().next();
                reqIdIdMap.clear();
            }

            if(thisId == null)
            {
                continue; // ignore it. this cert is not requested by me
            }

            ResultEntryType resultEntry;
            if(status == PKIStatus.GRANTED || status == PKIStatus.GRANTED_WITH_MODS)
            {
                CertifiedKeyPair cvk = certResp.getCertifiedKeyPair();
                if(cvk == null)
                {
                    return null;
                }

                CMPCertificate cmpCert = cvk.getCertOrEncCert().getCertificate();
                if(cmpCert == null)
                {
                    return null;
                }

                resultEntry = new EnrollCertResultEntryType(thisId, cmpCert, status);

                if(isImplicitConfirm == false)
                {
                    requireConfirm = true;
                    X509CertificateHolder certHolder = null;
                    try
                    {
                        certHolder = new X509CertificateHolder(cmpCert.getEncoded());
                    }catch(IOException e)
                    {
                        resultEntry = new ErrorResultEntryType(thisId, ClientErrorCode.PKIStatus_RESPONSE_ERROR,
                                ClientErrorCode.PKIFailureInfo_CERT_ENCODING_ERROR, "error while decode the certificate");
                    }

                    if(certHolder != null)
                    {
                        certConfirmBuilder.addAcceptedCertificate(certHolder, certReqId);
                    }
                }
            }
            else
            {
                PKIFreeText statusString = statusInfo.getStatusString();
                String errorMessage = statusString == null ? null : statusString.getStringAt(0).getString();
                int failureInfo = statusInfo.getFailInfo().intValue();

                resultEntry = new ErrorResultEntryType(thisId, status, failureInfo, errorMessage);
            }
            result.addResultEntry(resultEntry);
        }

        if(reqIdIdMap.isEmpty() == false)
        {
            for(BigInteger reqId : reqIdIdMap.keySet())
            {
                ErrorResultEntryType ere = new ErrorResultEntryType(reqIdIdMap.get(reqId), ClientErrorCode.PKIStatus_NO_ANSWER);
                result.addResultEntry(ere);
            }
        }

        if(requireConfirm == false)
        {
            return result;
        }

        PKIMessage confirmRequest = buildCertConfirmRequest(response.getPkiMessage().getHeader().getTransactionID(),
                certConfirmBuilder);

        response = signAndSend(confirmRequest);

        errorResult = checkAndBuildErrorResultIfRequired(response);
        if(errorResult != null)
        {
            return errorResult;
        }

        if(PKIBody.TYPE_ERROR == bodyType)
        {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            return buildErrorResult(content);
        }

        return result;
    }

    private PKIMessage buildCertConfirmRequest(
            ASN1OctetString tid,
            CertificateConfirmationContentBuilder certConfirmBuilder)
    throws CmpRequestorException
    {
        PKIHeader header = buildPKIHeader(implicitConfirm, tid, null);
        CertificateConfirmationContent certConfirm;
        try
        {
            certConfirm = certConfirmBuilder.build(digesetCalculatorProvider);
        } catch (CMPException e)
        {
            throw new CmpRequestorException(e);
        }
        PKIBody body = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, certConfirm.toASN1Structure());
        return new PKIMessage(header, body);
    }

    private PKIMessage buildMessageWithGeneralMsgContent(ASN1ObjectIdentifier type)
    throws CmpRequestorException
    {
        PKIHeader header = buildPKIHeader(null);
        InfoTypeAndValue itv = new InfoTypeAndValue(type);
        GenMsgContent genMsgContent = new GenMsgContent(itv);
        PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);

        PKIMessage pkiMessage = new PKIMessage(header, body);
        return pkiMessage;
    }

    private PKIMessage buildRevocateCertRequest(RevocateCertRequestType request)
    throws CmpRequestorException
    {
        PKIHeader header = buildPKIHeader(null);

        List<RevocateCertRequestEntryType> requestEntries = request.getRequestEntries();
        List<RevDetails> revDetailsArray = new ArrayList<RevDetails>(requestEntries.size());
        for(RevocateCertRequestEntryType requestEntry : requestEntries)
        {
            CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
            certTempBuilder.setIssuer(requestEntry.getIssuer());
            certTempBuilder.setSerialNumber(new ASN1Integer(requestEntry.getSerialNumber()));

            Date invalidityDate = requestEntry.getInvalidityDate();
            Extension[] extensions = new Extension[invalidityDate == null ? 1 : 2];

            try
            {
                DEREnumerated reason = new DEREnumerated(requestEntry.getReason());
                extensions[0] = new Extension(org.bouncycastle.asn1.x509.X509Extension.reasonCode,
                        true, new DEROctetString(reason.getEncoded()));

                if(invalidityDate != null)
                {
                    ASN1GeneralizedTime time = new ASN1GeneralizedTime(invalidityDate);
                    extensions[1] = new Extension(org.bouncycastle.asn1.x509.X509Extension.invalidityDate,
                        true, new DEROctetString(time.getEncoded()));
                }
            }catch(IOException e)
            {
                throw new CmpRequestorException(e);
            }
            Extensions exts = new Extensions(extensions);

            RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);
            revDetailsArray.add(revDetails);
        }

        RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));

        PKIBody body = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content);

        PKIMessage pkiMessage = new PKIMessage(header, body);
        return pkiMessage;
    }

    private PKIMessage buildPKIMessage(P10EnrollCertRequestType p10Req)
    {
        InfoTypeAndValue certProfileInfo = null;
        if(p10Req.getCertProfile() != null)
        {
            CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERT_PROFILE, p10Req.getCertProfile());
            certProfileInfo = new InfoTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                    new DERUTF8String(utf8Pairs.getEncoded()));
        }

        PKIHeader header = buildPKIHeader(implicitConfirm, null, certProfileInfo);
        PKIBody body = new PKIBody(PKIBody.TYPE_P10_CERT_REQ, p10Req.getP10Req());

        PKIMessage pkiMessage = new PKIMessage(header, body);
        return pkiMessage;
    }

    private PKIMessage buildPKIMessage(CertReqMsg req)
    {
        PKIHeader header = buildPKIHeader(implicitConfirm, null, null);

        int bodyType = PKIBody.TYPE_CERT_REQ;

        PKIBody body = new PKIBody(bodyType, new CertReqMessages(req));

        PKIMessage pkiMessage = new PKIMessage(header, body);
        return pkiMessage;
    }

    private PKIMessage buildPKIMessage(EnrollCertRequestType req)
    {
        PKIHeader header = buildPKIHeader(implicitConfirm, null, null);

        List<EnrollCertRequestEntryType> reqEntries = req.getRequestEntries();
        CertReqMsg[] certReqMsgs = new CertReqMsg[reqEntries.size()];

        for(int i=0; i<reqEntries.size(); i++)
        {
            EnrollCertRequestEntryType reqEntry = reqEntries.get(i);
            AttributeTypeAndValue certProfileInfo = null;
            if(reqEntry.getCertProfile() != null)
            {
                CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERT_PROFILE, reqEntry.getCertProfile());
                if(reqEntry.getOrigCertProfile() != null)
                {
                    utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_ORIG_CERT_PROFILE, reqEntry.getOrigCertProfile());
                }

                certProfileInfo = new AttributeTypeAndValue(
                        CMPObjectIdentifiers.regInfo_utf8Pairs,
                        new DERUTF8String(utf8Pairs.getEncoded()));
            }

            certReqMsgs[i] = new CertReqMsg(
                    reqEntry.getCertReq(),reqEntry.getPopo(),
                    (certProfileInfo == null) ? null : new AttributeTypeAndValue[]{certProfileInfo});
        }

        int bodyType;
        switch(req.getType())
        {
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
    }

    public PKIMessage envelope(CertReqMsg req)
    throws CmpRequestorException
    {
        PKIMessage request = buildPKIMessage(req);
        return sign(request);
    }

}
