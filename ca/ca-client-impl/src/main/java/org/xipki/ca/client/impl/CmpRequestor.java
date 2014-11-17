/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.client.impl;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
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
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.client.api.dto.ErrorResultType;
import org.xipki.ca.common.cmp.CmpUtil;
import org.xipki.ca.common.cmp.ProtectionResult;
import org.xipki.ca.common.cmp.ProtectionVerificationResult;
import org.xipki.ca.common.cmp.PKIResponse;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.CustomObjectIdentifiers;
import org.xipki.common.SecurityUtil;
import org.xipki.common.ParamChecker;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public abstract class CmpRequestor
{
    private static final Logger LOG = LoggerFactory.getLogger(CmpRequestor.class);
    private static GeneralName DUMMY_RECIPIENT = new GeneralName(new X500Name("CN=DUMMY"));

    private final  Random random = new Random();

    private final ConcurrentContentSigner requestor;
    private final GeneralName sender;

    private X509Certificate responderCert;
    private GeneralName recipient;
    private String c14nRecipientName;

    protected final SecurityFactory securityFactory;
    protected boolean signRequest;
    private boolean sendRequestorCert = false;

    public CmpRequestor(X509Certificate requestorCert,
            X509Certificate responderCert,
            SecurityFactory securityFactory)
    {
        ParamChecker.assertNotNull("requestorCert", requestorCert);
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        this.requestor = null;
        this.securityFactory = securityFactory;
        this.signRequest = false;

        X500Name x500Name = X500Name.getInstance(requestorCert.getSubjectX500Principal().getEncoded());
        this.sender = new GeneralName(x500Name);

        if(responderCert != null)
        {
            setResponderCert(responderCert);
        }
    }

    public CmpRequestor(ConcurrentContentSigner requestor,
            X509Certificate responderCert,
            SecurityFactory securityFactory)
    {
        this(requestor,responderCert, securityFactory, true);
    }

    public CmpRequestor(ConcurrentContentSigner requestor,
            X509Certificate responderCert,
            SecurityFactory securityFactory,
            boolean signRequest)
    {
        ParamChecker.assertNotNull("requestor", requestor);
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        this.requestor = requestor;
        this.securityFactory = securityFactory;
        this.signRequest = signRequest;

        X500Name x500Name = X500Name.getInstance(requestor.getCertificate().getSubjectX500Principal().getEncoded());
        this.sender = new GeneralName(x500Name);

        if(responderCert != null)
        {
            setResponderCert(responderCert);
        }
    }

    private void setResponderCert(X509Certificate responderCert)
    {
        ParamChecker.assertNotNull("responderCert", responderCert);

        this.responderCert = responderCert;
        X500Name subject = X500Name.getInstance(responderCert.getSubjectX500Principal().getEncoded());
        this.recipient = new GeneralName(subject);
        this.c14nRecipientName = canonicalizeSortedName(subject);
    }

    protected abstract byte[] send(byte[] request)
    throws IOException;

    protected PKIMessage sign(PKIMessage request)
    throws CmpRequestorException
    {
        if(requestor == null)
        {
            throw new CmpRequestorException("No request signer is configured");
        }

        if(responderCert == null)
        {
            throw new CmpRequestorException("CMP responder is not configured");
        }

        try
        {
            request = CmpUtil.addProtection(request, requestor, sender, sendRequestorCert);
        } catch (CMPException | NoIdleSignerException e)
        {
            throw new CmpRequestorException("Could not sign the request", e);
        }
        return request;
    }

    protected PKIResponse signAndSend(PKIMessage request)
    throws CmpRequestorException
    {
        if(signRequest)
        {
            request = sign(request);
        }

        if(responderCert == null)
        {
            throw new CmpRequestorException("CMP responder is not configured");
        }

        byte[] encodedRequest;
        try
        {
            encodedRequest = request.getEncoded();
        } catch (IOException e)
        {
            LOG.error("Error while encode the PKI request {}", request);
            throw new CmpRequestorException(e);
        }

        byte[] encodedResponse;
        try
        {
            encodedResponse = send(encodedRequest);
        } catch (IOException e)
        {
            LOG.error("Error while send the PKI request {} to server", request);
            throw new CmpRequestorException("TRANSPORT_ERROR", e);
        }

        GeneralPKIMessage response;
        try
        {
            response = new GeneralPKIMessage(encodedResponse);
        } catch (IOException e)
        {
            if(LOG.isErrorEnabled())
            {
                LOG.error("Error while decode the received PKI message: {}", Hex.toHexString(encodedResponse));
            }
            throw new CmpRequestorException(e);
        }

        PKIHeader respHeader = response.getHeader();
        ASN1OctetString tid = respHeader.getTransactionID();
        GeneralName recipient = respHeader.getRecipient();
        if(sender.equals(recipient) == false)
        {
            LOG.warn("tid={}: Unknown CMP requestor '{}'", tid, recipient);
        }

        PKIResponse ret = new PKIResponse(response);
        if(response.hasProtection())
        {
            try
            {
                ProtectionVerificationResult verifyProtection = verifyProtection(
                        Hex.toHexString(tid.getOctets()), response, responderCert);
                ret.setProtectionVerificationResult(verifyProtection);
            } catch (InvalidKeyException | OperatorCreationException | CMPException e)
            {
                throw new CmpRequestorException(e);
            }
        }
        else if(signRequest)
        {
            PKIBody respBody = response.getBody();
            int bodyType = respBody.getType();
            if(bodyType != PKIBody.TYPE_ERROR)
            {
                throw new CmpRequestorException("Response is not signed");
            }
        }

        return ret;
    }

    protected ASN1Encodable extractGeneralRepContent(PKIResponse response, String exepectedType)
    throws CmpRequestorException
    {
        return extractGeneralRepContent(response, exepectedType, true);
    }

    private ASN1Encodable extractGeneralRepContent(PKIResponse response, String exepectedType, boolean requireProtectionCheck)
    throws CmpRequestorException
    {
        if(requireProtectionCheck)
        {
            ErrorResultType errorResult = checkAndBuildErrorResultIfRequired(response);
            if(errorResult != null)
            {
                throw new CmpRequestorException(SecurityUtil.formatPKIStatusInfo(
                        errorResult.getStatus(), errorResult.getPkiFailureInfo(), errorResult.getStatusMessage()));
            }
        }

        PKIBody respBody = response.getPkiMessage().getBody();
        int bodyType = respBody.getType();

        if(PKIBody.TYPE_ERROR == bodyType)
        {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            throw new CmpRequestorException(SecurityUtil.formatPKIStatusInfo(
                    content.getPKIStatusInfo()));
        }
        else if(PKIBody.TYPE_GEN_REP != bodyType)
        {
            throw new CmpRequestorException("Unknown PKI body type " + bodyType +
                    " instead the exceptected [" + PKIBody.TYPE_GEN_REP  + ", " +
                    PKIBody.TYPE_ERROR + "]");
        }

        GenRepContent genRep = (GenRepContent) respBody.getContent();

        InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
        InfoTypeAndValue itv = null;
        if(itvs != null && itvs.length > 0)
        {
            for(InfoTypeAndValue _itv : itvs)
            {
                if(exepectedType.equals(_itv.getInfoType().getId()))
                {
                    itv = _itv;
                    break;
                }
            }
        }
        if(itv == null)
        {
            throw new CmpRequestorException("The response does not contain InfoTypeAndValue "
                    + exepectedType);
        }

        return itv.getInfoValue();
    }

    public void autoConfigureResponder()
    throws CmpRequestorException
    {
        PKIMessage request = buildMessageWithGeneralMsgContent(
                new ASN1ObjectIdentifier(CustomObjectIdentifiers.id_cmp_getCmpResponderCert), null);

        if(signRequest)
        {
            if(requestor == null)
            {
                throw new CmpRequestorException("No request signer is configured");
            }

            try
            {
                request = CmpUtil.addProtection(request, requestor, sender, false);
            } catch (CMPException | NoIdleSignerException e)
            {
                throw new CmpRequestorException("Could not sign the request", e);
            }
        }

        byte[] encodedRequest;
        try
        {
            encodedRequest = request.getEncoded();
        } catch (IOException e)
        {
            LOG.error("Error while encode the PKI request {}", request);
            throw new CmpRequestorException(e);
        }

        byte[] encodedResponse;
        try
        {
            encodedResponse = send(encodedRequest);
        } catch (IOException e)
        {
            LOG.error("Error while send the PKI request {} to server", request);
            throw new CmpRequestorException("TRANSPORT_ERROR", e);
        }

        GeneralPKIMessage response;
        try
        {
            response = new GeneralPKIMessage(encodedResponse);
        } catch (IOException e)
        {
            if(LOG.isErrorEnabled())
            {
                LOG.error("Error while decode the received PKI message: {}", Hex.toHexString(encodedResponse));
            }
            throw new CmpRequestorException(e);
        }

        PKIHeader respHeader = response.getHeader();
        ASN1OctetString tid = respHeader.getTransactionID();
        GeneralName recipient = respHeader.getRecipient();
        if(sender.equals(recipient) == false)
        {
            LOG.warn("tid={}: Unknown CMP requestor '{}'", tid, recipient);
        }

        PKIResponse pkiResp = new PKIResponse(response);
        if(response.hasProtection() == false && signRequest)
        {
            PKIBody respBody = response.getBody();
            int bodyType = respBody.getType();
            if(bodyType != PKIBody.TYPE_ERROR)
            {
                throw new CmpRequestorException("Response is not signed");
            }
        }

        ASN1Encodable itvValue = extractGeneralRepContent(pkiResp,
                CustomObjectIdentifiers.id_cmp_getCmpResponderCert, false);
        Certificate cert = Certificate.getInstance(itvValue);

        X509Certificate x509Cert;
        try
        {
            x509Cert = SecurityUtil.parseCert(cert.getEncoded());
        } catch (CertificateException | IOException e)
        {
            throw new CmpRequestorException("Returned certificate is invalid: " + e.getMessage(), e);
        }

        if(response.hasProtection())
        {
            try
            {
                ProtectionVerificationResult verifyProtection = verifyProtection(
                        Hex.toHexString(tid.getOctets()), response, x509Cert);

                if(verifyProtection.getProtectionResult() != ProtectionResult.VALID)
                {
                    throw new CmpRequestorException(SecurityUtil.formatPKIStatusInfo(
                            ClientErrorCode.PKIStatus_RESPONSE_ERROR,
                            PKIFailureInfo.badMessageCheck, "message check of the response failed"));
                }
            } catch (InvalidKeyException | OperatorCreationException | CMPException e)
            {
                throw new CmpRequestorException(e);
            }
        }

        setResponderCert(x509Cert);
    }

    protected PKIHeader buildPKIHeader(ASN1OctetString tid)
    {
        return buildPKIHeader(false, tid, null, (InfoTypeAndValue[]) null);
    }

    protected PKIHeader buildPKIHeader(ASN1OctetString tid, String username)
    {
        return buildPKIHeader(false, tid, username, (InfoTypeAndValue[]) null);
    }

    protected PKIHeader buildPKIHeader(boolean addImplictConfirm,
            ASN1OctetString tid, String username,
            InfoTypeAndValue... additionalGeneralInfos)
    {
        PKIHeaderBuilder hBuilder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                sender,
                recipient != null ? recipient : DUMMY_RECIPIENT);
        hBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

        if(tid == null)
        {
            tid = new DEROctetString(randomTransactionId());
        }
        hBuilder.setTransactionID(tid);

        List<InfoTypeAndValue> itvs = new ArrayList<>(2);
        if(addImplictConfirm)
        {
            itvs.add(CmpUtil.getImplictConfirmGeneralInfo());
        }
        if(username != null && username.isEmpty() == false)
        {
            CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_USER, username);
            itvs.add(CmpUtil.buildInfoTypeAndValue(utf8Pairs));
        }

        if(additionalGeneralInfos != null)
        {
            for(InfoTypeAndValue itv : additionalGeneralInfos)
            {
                if(itv != null)
                {
                    itvs.add(itv);
                }
            }
        }

        if(itvs.isEmpty() == false)
        {
            hBuilder.setGeneralInfo(itvs.toArray(new InfoTypeAndValue[0]));
        }

        return hBuilder.build();
    }

    protected ErrorResultType buildErrorResult(ErrorMsgContent bodyContent)
    {
        org.xipki.ca.common.cmp.PKIStatusInfo statusInfo = new org.xipki.ca.common.cmp.PKIStatusInfo(
                bodyContent.getPKIStatusInfo());
        return new ErrorResultType(statusInfo.getStatus(), statusInfo.getPkiFailureInfo(), statusInfo.getStatusMessage());
    }

    private byte[] randomTransactionId()
    {
        byte[] tid = new byte[20];
        random.nextBytes(tid);
        return tid;
    }

    private ProtectionVerificationResult verifyProtection(String tid, GeneralPKIMessage pkiMessage,
            X509Certificate cert)
    throws CMPException, InvalidKeyException, OperatorCreationException
    {
        ProtectedPKIMessage pMsg = new ProtectedPKIMessage(pkiMessage);

        if(pMsg.hasPasswordBasedMacProtection())
        {
            LOG.warn("NOT_SIGNAUTRE_BASED: " + pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
            return new ProtectionVerificationResult(null, ProtectionResult.NOT_SIGNATURE_BASED);
        }

        PKIHeader h = pMsg.getHeader();

        if(c14nRecipientName != null)
        {
            boolean authorizedResponder = true;
            if(h.getSender().getTagNo() != GeneralName.directoryName)
            {
                authorizedResponder = false;
            }
            else
            {
                String c14nMsgSender = canonicalizeSortedName((X500Name) h.getSender().getName());
                authorizedResponder = c14nRecipientName.equalsIgnoreCase(c14nMsgSender);
            }

            if(authorizedResponder == false)
            {
                LOG.warn("tid={}: not authorized responder {}", tid, h.getSender());
                return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
            }
        }

        ContentVerifierProvider verifierProvider =
                securityFactory.getContentVerifierProvider(cert);
        if(verifierProvider == null)
        {
            LOG.warn("tid={}: not authorized responder {}", tid, h.getSender());
            return new ProtectionVerificationResult(cert, ProtectionResult.SENDER_NOT_AUTHORIZED);
        }

        boolean signatureValid = pMsg.verify(verifierProvider);
        return new ProtectionVerificationResult(cert,
                signatureValid ? ProtectionResult.VALID : ProtectionResult.INVALID);
    }

    protected PKIMessage buildMessageWithGeneralMsgContent(ASN1ObjectIdentifier type, ASN1Encodable value)
    throws CmpRequestorException
    {
        PKIHeader header = buildPKIHeader(null);
        InfoTypeAndValue itv;
        if(value != null)
        {
            itv = new InfoTypeAndValue(type, value);
        }
        else
        {
            itv = new InfoTypeAndValue(type);
        }
        GenMsgContent genMsgContent = new GenMsgContent(itv);
        PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);

        PKIMessage pkiMessage = new PKIMessage(header, body);
        return pkiMessage;
    }

    protected ErrorResultType checkAndBuildErrorResultIfRequired(PKIResponse response)
    {
        ProtectionVerificationResult protectionVerificationResult = response.getProtectionVerificationResult();
        if(response.hasProtection() == false)
        {
            return null;
        }

        boolean accept = protectionVerificationResult != null &&
                    protectionVerificationResult.getProtectionResult() == ProtectionResult.VALID;
        if(accept)
        {
            return null;
        }

        return new ErrorResultType(ClientErrorCode.PKIStatus_RESPONSE_ERROR,
                PKIFailureInfo.badMessageCheck,
                "message check of the response failed");
    }

    public boolean isSendRequestorCert()
    {
        return sendRequestorCert;
    }

    public void setSendRequestorCert(boolean sendRequestorCert)
    {
        this.sendRequestorCert = sendRequestorCert;
    }

    private static String canonicalizeSortedName(X500Name name)
    {
        return SecurityUtil.getRFC4519Name(SecurityUtil.sortX509Name(name));
    }
}
