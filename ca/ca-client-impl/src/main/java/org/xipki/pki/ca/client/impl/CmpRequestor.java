/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.RequestResponsePair;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.pki.ca.client.api.PKIErrorException;
import org.xipki.pki.ca.common.cmp.CmpUtf8Pairs;
import org.xipki.pki.ca.common.cmp.CmpUtil;
import org.xipki.pki.ca.common.cmp.PKIResponse;
import org.xipki.pki.ca.common.cmp.ProtectionResult;
import org.xipki.pki.ca.common.cmp.ProtectionVerificationResult;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.ObjectIdentifiers;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.util.SecurityUtil;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public abstract class CmpRequestor {
    private static final Logger LOG = LoggerFactory.getLogger(CmpRequestor.class);

    private final  Random random = new Random();

    private final ConcurrentContentSigner requestor;
    private final GeneralName sender;

    private final X509Certificate responderCert;
    private final GeneralName recipient;
    private final String c14nRecipientName;

    protected final SecurityFactory securityFactory;
    protected boolean signRequest;
    private boolean sendRequestorCert = false;

    public CmpRequestor(
            final X509Certificate requestorCert,
            final X509Certificate responderCert,
            final SecurityFactory securityFactory) {
        ParamUtil.assertNotNull("requestorCert", requestorCert);
        ParamUtil.assertNotNull("responderCert", responderCert);
        ParamUtil.assertNotNull("securityFactory", securityFactory);

        this.requestor = null;
        this.securityFactory = securityFactory;
        this.signRequest = false;

        X500Name x500Name = X500Name.getInstance(
                requestorCert.getSubjectX500Principal().getEncoded());
        this.sender = new GeneralName(x500Name);

        this.responderCert = responderCert;
        X500Name subject = X500Name.getInstance(
                responderCert.getSubjectX500Principal().getEncoded());
        this.recipient = new GeneralName(subject);
        this.c14nRecipientName = getSortedRFC4519Name(subject);
    }

    public CmpRequestor(
            final ConcurrentContentSigner requestor,
            final X509Certificate responderCert,
            final SecurityFactory securityFactory) {
        this(requestor, responderCert, securityFactory, true);
    }

    public CmpRequestor(ConcurrentContentSigner requestor,
            final X509Certificate responderCert,
            final SecurityFactory securityFactory,
            final boolean signRequest) {
        ParamUtil.assertNotNull("requestor", requestor);
        ParamUtil.assertNotNull("responderCert", responderCert);
        ParamUtil.assertNotNull("securityFactory", securityFactory);

        this.requestor = requestor;
        this.securityFactory = securityFactory;
        this.signRequest = signRequest;

        X500Name x500Name = X500Name.getInstance(
                requestor.getCertificate().getSubjectX500Principal().getEncoded());
        this.sender = new GeneralName(x500Name);

        this.responderCert = responderCert;
        X500Name subject = X500Name.getInstance(
                responderCert.getSubjectX500Principal().getEncoded());
        this.recipient = new GeneralName(subject);
        this.c14nRecipientName = getSortedRFC4519Name(subject);
    }

    protected abstract byte[] send(
            final byte[] request)
    throws IOException;

    protected PKIMessage sign(
            final PKIMessage request)
    throws CmpRequestorException {
        if (requestor == null) {
            throw new CmpRequestorException("no request signer is configured");
        }

        if (responderCert == null) {
            throw new CmpRequestorException("CMP responder is not configured");
        }

        try {
            return CmpUtil.addProtection(request, requestor, sender, sendRequestorCert);
        } catch (CMPException | NoIdleSignerException e) {
            throw new CmpRequestorException("could not sign the request", e);
        }
    }

    protected PKIResponse signAndSend(
            final PKIMessage request,
            final RequestResponseDebug debug)
    throws CmpRequestorException {
        PKIMessage _request;
        if (signRequest) {
            _request = sign(request);
        } else {
            _request = request;
        }

        if (responderCert == null) {
            throw new CmpRequestorException("CMP responder is not configured");
        }

        byte[] encodedRequest;
        try {
            encodedRequest = _request.getEncoded();
        } catch (IOException e) {
            LOG.error("error while encode the PKI request {}", _request);
            throw new CmpRequestorException(e.getMessage(), e);
        }

        RequestResponsePair reqResp = null;
        if (debug != null) {
            reqResp = new RequestResponsePair();
            debug.add(reqResp);
            reqResp.setRequest(encodedRequest);
        }

        byte[] encodedResponse;
        try {
            encodedResponse = send(encodedRequest);
        } catch (IOException e) {
            LOG.error("error while send the PKI request {} to server", _request);
            throw new CmpRequestorException("TRANSPORT_ERROR", e);
        }

        if (reqResp != null) {
            reqResp.setResponse(encodedResponse);
        }

        GeneralPKIMessage response;
        try {
            response = new GeneralPKIMessage(encodedResponse);
        } catch (IOException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("error while decode the received PKI message: {}",
                        Hex.toHexString(encodedResponse));
            }
            throw new CmpRequestorException(e.getMessage(), e);
        }

        PKIHeader respHeader = response.getHeader();
        ASN1OctetString tid = respHeader.getTransactionID();
        GeneralName recipient = respHeader.getRecipient();
        if (!sender.equals(recipient)) {
            LOG.warn("tid={}: unknown CMP requestor '{}'", tid, recipient);
        }

        PKIResponse ret = new PKIResponse(response);
        if (response.hasProtection()) {
            try {
                ProtectionVerificationResult verifyProtection = verifyProtection(
                        Hex.toHexString(tid.getOctets()), response, responderCert);
                ret.setProtectionVerificationResult(verifyProtection);
            } catch (InvalidKeyException | OperatorCreationException | CMPException e) {
                throw new CmpRequestorException(e.getMessage(), e);
            }
        } else if (signRequest) {
            PKIBody respBody = response.getBody();
            int bodyType = respBody.getType();
            if (bodyType != PKIBody.TYPE_ERROR) {
                throw new CmpRequestorException("response is not signed");
            }
        }

        return ret;
    }

    protected ASN1Encodable extractGeneralRepContent(
            final PKIResponse response,
            final String exepectedType)
    throws CmpRequestorException, PKIErrorException {
        return extractGeneralRepContent(response, exepectedType, true);
    }

    protected ASN1Encodable extractXipkiActionRepContent(
            final PKIResponse response,
            final int action)
    throws CmpRequestorException, PKIErrorException {
        ASN1Encodable itvValue = extractGeneralRepContent(response,
                ObjectIdentifiers.id_xipki_cm_cmpGenmsg.getId(), true);
        return extractXipkiActionContent(itvValue, action);
    }

    protected ASN1Encodable extractXipkiActionContent(
            final ASN1Encodable itvValue,
            final int action)
    throws CmpRequestorException {
        ASN1Sequence seq;
        try {
            seq = ASN1Sequence.getInstance(itvValue);
        } catch (IllegalArgumentException e) {
            throw new CmpRequestorException("invalid syntax of the response");
        }
        int n = seq.size();
        if (n != 1 && n != 2) {
            throw new CmpRequestorException("invalid syntax of the response");
        }

        int _action;
        try {
            _action = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue().intValue();
        } catch (IllegalArgumentException e) {
            throw new CmpRequestorException("invalid syntax of the response");
        }

        if (action != _action) {
            throw new CmpRequestorException("received XiPKI action '" + _action
                    + "' instead the exceptected '" + action  + "'");
        }

        return (n == 1)
                ? null
                : seq.getObjectAt(1);
    }

    private ASN1Encodable extractGeneralRepContent(
            final PKIResponse response,
            final String exepectedType,
            final boolean requireProtectionCheck)
    throws CmpRequestorException, PKIErrorException {
        if (requireProtectionCheck) {
            checkProtection(response);
        }

        PKIBody respBody = response.getPkiMessage().getBody();
        int bodyType = respBody.getType();

        if (PKIBody.TYPE_ERROR == bodyType) {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            throw new CmpRequestorException(SecurityUtil.formatPKIStatusInfo(
                    content.getPKIStatusInfo()));
        } else if (PKIBody.TYPE_GEN_REP != bodyType) {
            throw new CmpRequestorException("unknown PKI body type " + bodyType
                    + " instead the exceptected [" + PKIBody.TYPE_GEN_REP  + ", "
                    + PKIBody.TYPE_ERROR + "]");
        }

        GenRepContent genRep = (GenRepContent) respBody.getContent();

        InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
        InfoTypeAndValue itv = null;
        if (itvs != null && itvs.length > 0) {
            for (InfoTypeAndValue _itv : itvs) {
                if (exepectedType.equals(_itv.getInfoType().getId())) {
                    itv = _itv;
                    break;
                }
            }
        }
        if (itv == null) {
            throw new CmpRequestorException("the response does not contain InfoTypeAndValue "
                    + exepectedType);
        }

        return itv.getInfoValue();
    }

    protected PKIHeader buildPKIHeader(
            final ASN1OctetString tid) {
        return buildPKIHeader(false, tid, (CmpUtf8Pairs) null, (InfoTypeAndValue[]) null);
    }

    protected PKIHeader buildPKIHeader(
            final ASN1OctetString tid,
            final String username) {
        return buildPKIHeader(false, tid, username);
    }

    protected PKIHeader buildPKIHeader(
            final boolean addImplictConfirm,
            final ASN1OctetString tid,
            final String username) {
        CmpUtf8Pairs utf8Pairs = null;
        if (StringUtil.isNotBlank(username)) {
            utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_USER, username);
        }
        return buildPKIHeader(addImplictConfirm, tid, utf8Pairs, (InfoTypeAndValue[]) null);
    }

    protected PKIHeader buildPKIHeader(
            final boolean addImplictConfirm,
            final ASN1OctetString tid,
            final CmpUtf8Pairs utf8Pairs,
            final InfoTypeAndValue... additionalGeneralInfos) {
        if (additionalGeneralInfos != null) {
            for (InfoTypeAndValue itv : additionalGeneralInfos) {
                ASN1ObjectIdentifier type = itv.getInfoType();
                if (CMPObjectIdentifiers.it_implicitConfirm.equals(type)) {
                    throw new IllegalArgumentException(""
                            + "additionGeneralInfos contains unpermitted ITV implicitConfirm");
                }

                if (CMPObjectIdentifiers.regInfo_utf8Pairs.equals(type)) {
                    throw new IllegalArgumentException(""
                            + "additionGeneralInfos contains unpermitted ITV utf8Pairs");
                }
            }
        }

        PKIHeaderBuilder hBuilder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                sender,
                recipient);
        hBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

        ASN1OctetString _tid;
        if (tid == null) {
            _tid = new DEROctetString(randomTransactionId());
        } else {
            _tid = tid;
        }

        hBuilder.setTransactionID(_tid);

        List<InfoTypeAndValue> itvs = new ArrayList<>(2);
        if (addImplictConfirm) {
            itvs.add(CmpUtil.getImplictConfirmGeneralInfo());
        }

        if (utf8Pairs != null) {
            itvs.add(CmpUtil.buildInfoTypeAndValue(utf8Pairs));
        }

        if (additionalGeneralInfos != null) {
            for (InfoTypeAndValue itv : additionalGeneralInfos) {
                if (itv != null) {
                    itvs.add(itv);
                }
            }
        }

        if (CollectionUtil.isNotEmpty(itvs)) {
            hBuilder.setGeneralInfo(itvs.toArray(new InfoTypeAndValue[0]));
        }

        return hBuilder.build();
    }

    protected PKIErrorException buildErrorResult(
            final ErrorMsgContent bodyContent) {
        org.xipki.pki.ca.common.cmp.PKIStatusInfo statusInfo =
                new org.xipki.pki.ca.common.cmp.PKIStatusInfo(bodyContent.getPKIStatusInfo());
        return new PKIErrorException(statusInfo.getStatus(), statusInfo.getPkiFailureInfo(),
                statusInfo.getStatusMessage());
    }

    private byte[] randomTransactionId() {
        byte[] tid = new byte[20];
        random.nextBytes(tid);
        return tid;
    }

    private ProtectionVerificationResult verifyProtection(
            final String tid,
            final GeneralPKIMessage pkiMessage,
            final X509Certificate cert)
    throws CMPException, InvalidKeyException, OperatorCreationException {
        ProtectedPKIMessage pMsg = new ProtectedPKIMessage(pkiMessage);

        if (pMsg.hasPasswordBasedMacProtection()) {
            LOG.warn("NOT_SIGNAUTRE_BASED: "
                    + pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
            return new ProtectionVerificationResult(null, ProtectionResult.NOT_SIGNATURE_BASED);
        }

        PKIHeader h = pMsg.getHeader();

        if (c14nRecipientName != null) {
            boolean authorizedResponder = true;
            if (h.getSender().getTagNo() != GeneralName.directoryName) {
                authorizedResponder = false;
            } else {
                String c14nMsgSender = getSortedRFC4519Name((X500Name) h.getSender().getName());
                authorizedResponder = c14nRecipientName.equalsIgnoreCase(c14nMsgSender);
            }

            if (!authorizedResponder) {
                LOG.warn("tid={}: not authorized responder '{}'", tid, h.getSender());
                return new ProtectionVerificationResult(null,
                        ProtectionResult.SENDER_NOT_AUTHORIZED);
            }
        }

        ContentVerifierProvider verifierProvider =
                securityFactory.getContentVerifierProvider(cert);
        if (verifierProvider == null) {
            LOG.warn("tid={}: not authorized responder '{}'", tid, h.getSender());
            return new ProtectionVerificationResult(cert, ProtectionResult.SENDER_NOT_AUTHORIZED);
        }

        boolean signatureValid = pMsg.verify(verifierProvider);
        ProtectionResult protRes = signatureValid
                ? ProtectionResult.VALID
                : ProtectionResult.INVALID;
        return new ProtectionVerificationResult(cert, protRes);
    }

    protected PKIMessage buildMessageWithXipkAction(
            final int action,
            final ASN1Encodable value)
    throws CmpRequestorException {
        PKIHeader header = buildPKIHeader(null);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(action));
        if (value != null) {
            v.add(value);
        }
        InfoTypeAndValue itv = new InfoTypeAndValue(ObjectIdentifiers.id_xipki_cm_cmpGenmsg,
                new DERSequence(v));
        GenMsgContent genMsgContent = new GenMsgContent(itv);
        PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);

        PKIMessage pkiMessage = new PKIMessage(header, body);
        return pkiMessage;
    }

    protected PKIMessage buildMessageWithGeneralMsgContent(
            final ASN1ObjectIdentifier type,
            final ASN1Encodable value)
    throws CmpRequestorException {
        PKIHeader header = buildPKIHeader(null);
        InfoTypeAndValue itv;
        if (value != null) {
            itv = new InfoTypeAndValue(type, value);
        } else {
            itv = new InfoTypeAndValue(type);
        }
        GenMsgContent genMsgContent = new GenMsgContent(itv);
        PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);

        PKIMessage pkiMessage = new PKIMessage(header, body);
        return pkiMessage;
    }

    protected void checkProtection(
            final PKIResponse response)
    throws PKIErrorException {
        ProtectionVerificationResult protectionVerificationResult =
                response.getProtectionVerificationResult();
        if (response.hasProtection()) {
            if (protectionVerificationResult == null
                    || protectionVerificationResult.getProtectionResult()
                            != ProtectionResult.VALID) {
                throw new PKIErrorException(ClientErrorCode.PKIStatus_RESPONSE_ERROR,
                        PKIFailureInfo.badMessageCheck,
                        "message check of the response failed");
            }
        }
    }

    public boolean isSendRequestorCert() {
        return sendRequestorCert;
    }

    public void setSendRequestorCert(
            final boolean sendRequestorCert) {
        this.sendRequestorCert = sendRequestorCert;
    }

    private static String getSortedRFC4519Name(
            final X500Name name) {
        return X509Util.getRFC4519Name(X509Util.sortX509Name(name));
    }
}
