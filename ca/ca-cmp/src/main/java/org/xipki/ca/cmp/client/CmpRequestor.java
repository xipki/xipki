/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
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
import org.xipki.ca.cmp.CmpUtil;
import org.xipki.ca.cmp.ProtectionResult;
import org.xipki.ca.cmp.ProtectionVerificationResult;
import org.xipki.ca.cmp.client.type.ErrorResultType;
import org.xipki.ca.cmp.server.PKIResponse;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public abstract class CmpRequestor
{
    private static final Logger LOG = LoggerFactory.getLogger(CmpRequestor.class);
    private final  Random random = new Random();

    private final ConcurrentContentSigner requestor;
    private final GeneralName sender;
    private final GeneralName recipient;

    private final X509Certificate responderCert;

    protected final SecurityFactory securityFactory;
    protected boolean signRequest;

    public CmpRequestor(X509Certificate requestorCert,
            X509Certificate responderCert,
            SecurityFactory securityFactory)
    {
        ParamChecker.assertNotNull("requestorCert", requestorCert);
        ParamChecker.assertNotNull("responderCert", responderCert);
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        this.requestor = null;
        this.responderCert = responderCert;
        this.securityFactory = securityFactory;
        this.signRequest = false;

        X500Name subject = X500Name.getInstance(responderCert.getSubjectX500Principal().getEncoded());
        this.recipient = new GeneralName(subject);

        X500Name x500Name = X500Name.getInstance(requestorCert.getSubjectX500Principal().getEncoded());
        this.sender = new GeneralName(x500Name);
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
        ParamChecker.assertNotNull("responderCert", responderCert);
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        this.requestor = requestor;
        this.responderCert = responderCert;
        this.securityFactory = securityFactory;
        this.signRequest = signRequest;

        X500Name subject = X500Name.getInstance(responderCert.getSubjectX500Principal().getEncoded());
        this.recipient = new GeneralName(subject);

        X500Name x500Name = X500Name.getInstance(requestor.getCertificate().getSubjectX500Principal().getEncoded());
        this.sender = new GeneralName(x500Name);
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

        try
        {
            request = CmpUtil.addProtection(request, requestor, sender, false);
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
            throw new CmpRequestorException(e);
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
                        Hex.toHexString(tid.getOctets()), response);
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

    public X509Certificate getResponderCert()
    {
        return responderCert;
    }

    protected PKIHeader buildPKIHeader(ASN1OctetString tid)
    {
        return buildPKIHeader(false, tid, null, null);
    }

    protected PKIHeader buildPKIHeader(ASN1OctetString tid, String username)
    {
        return buildPKIHeader(false, tid, username, null);
    }

    protected PKIHeader buildPKIHeader(boolean addImplictConfirm,
            ASN1OctetString tid, String username,
            InfoTypeAndValue generalInfo, InfoTypeAndValue... additionalGeneralInfos)
    {
        PKIHeaderBuilder hBuilder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                sender,
                recipient);
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

        if(itvs.isEmpty() == false)
        {
            hBuilder.setGeneralInfo(itvs.toArray(new InfoTypeAndValue[0]));
        }

        return hBuilder.build();
    }

    protected ErrorResultType buildErrorResult(ErrorMsgContent bodyContent)
    {
        PKIStatusInfo statusInfo = bodyContent.getPKIStatusInfo();
        int status = statusInfo.getStatus().intValue();
        int failureCode = statusInfo.getFailInfo().intValue();
        PKIFreeText text = statusInfo.getStatusString();
        String statusMessage = text == null ? null : text.getStringAt(0).getString();
        return new ErrorResultType(status, failureCode, statusMessage);
    }

    private byte[] randomTransactionId()
    {
        byte[] tid = new byte[20];
        random.nextBytes(tid);
        return tid;
    }

    private ProtectionVerificationResult verifyProtection(String tid, GeneralPKIMessage pkiMessage)
    throws CMPException, InvalidKeyException, OperatorCreationException
    {
        ProtectedPKIMessage pMsg = new ProtectedPKIMessage(pkiMessage);

        if(pMsg.hasPasswordBasedMacProtection())
        {
            LOG.warn("NOT_SIGNAUTRE_BASED: " + pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
            return new ProtectionVerificationResult(null, ProtectionResult.NOT_SIGNATURE_BASED);
        }

        PKIHeader h = pMsg.getHeader();
        if(recipient.equals(h.getSender()) == false)
        {
            LOG.warn("tid={}: not authorized responder {}", tid, h.getSender());
            return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
        }

        ContentVerifierProvider verifierProvider =
                securityFactory.getContentVerifierProvider(responderCert);
        if(verifierProvider == null)
        {
            LOG.warn("tid={}: not authorized requestor {}", tid, h.getSender());
            return new ProtectionVerificationResult(requestor, ProtectionResult.SENDER_NOT_AUTHORIZED);
        }

        boolean signatureValid = pMsg.verify(verifierProvider);
        return new ProtectionVerificationResult(requestor,
                signatureValid ? ProtectionResult.VALID : ProtectionResult.INVALID);
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

}
