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

package org.xipki.ca.cmp.client;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.util.Date;
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
import org.xipki.security.common.ParamChecker;

public abstract class CmpRequestor
{
    private static final Logger LOG = LoggerFactory.getLogger(CmpRequestor.class);
    private final  Random random = new Random();

    private final ConcurrentContentSigner requestor;
    private final GeneralName sender;
    private final GeneralName recipient;

    private final X509Certificate responderCert;

    private int signserviceTimeout = 5000; // 5 seconds
    protected final SecurityFactory securityFactory;

    public CmpRequestor(
            ConcurrentContentSigner requestor,
            X509Certificate responderCert,
            SecurityFactory securityFactory)
    {
        ParamChecker.assertNotNull("requestor", requestor);
        ParamChecker.assertNotNull("responderCert", responderCert);
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        this.requestor = requestor;
        this.responderCert = responderCert;
        this.securityFactory = securityFactory;

        X500Name subject = X500Name.getInstance(responderCert.getSubjectX500Principal().getEncoded());
        this.recipient = new GeneralName(subject);

        X500Name x500Name = X500Name.getInstance(requestor.getCertificate().getSubjectX500Principal().getEncoded());
        this.sender = new GeneralName(x500Name);
    }

    protected abstract byte[] send(byte[] request) throws IOException;

    public void setSignserviceTimeout(int signserviceTimeout)
    {
        if(signserviceTimeout < 0)
        {
            throw new IllegalArgumentException("negative signserviceTimeout is not allowed: " + signserviceTimeout);
        }
        this.signserviceTimeout = signserviceTimeout;
    }

    protected PKIMessage sign(PKIMessage request)
    throws CmpRequestorException
    {
        try {
            request = CmpUtil.addProtection(request, requestor, sender, signserviceTimeout);
        } catch (CMPException e) {
            throw new CmpRequestorException("Could not sign the request", e);
        } catch (NoIdleSignerException e) {
            throw new CmpRequestorException("Could not sign the request", e);
        }
        return request;
    }

    protected PKIResponse signAndSend(PKIMessage request)
    throws CmpRequestorException
    {
        request = sign(request);

        byte[] encodedRequest;
        try {
            encodedRequest = request.getEncoded();
        } catch (IOException e) {
            LOG.error("Error while encode the PKI request {}", request);
            throw new CmpRequestorException(e);
        }

        byte[] encodedResponse;
        try {
            encodedResponse = send(encodedRequest);
        } catch (IOException e) {
            LOG.error("Error while send the PKI request {} to server", request);
            throw new CmpRequestorException(e);
        }

        GeneralPKIMessage response;
        try {
            response = new GeneralPKIMessage(encodedResponse);
        } catch (IOException e) {
            LOG.error("Error while decode the received PKI message: {}", Hex.toHexString(encodedResponse));
            throw new CmpRequestorException(e);
        }

        PKIHeader respHeader = response.getHeader();
        ASN1OctetString tid = respHeader.getTransactionID();
        GeneralName recipient = respHeader.getRecipient();
        if(! sender.equals(recipient))
        {
            LOG.warn("tid={}: Unknown CMP requestor '{}'", tid, recipient);
        }

        PKIResponse ret = new PKIResponse(response);
        if(response.hasProtection())
        {
            try {
                ProtectionVerificationResult verifyProtection = verifyProtection(Hex.toHexString(tid.getOctets()), response);
                ret.setProtectionVerificationResult(verifyProtection);
            } catch (InvalidKeyException e) {
                throw new CmpRequestorException(e);
            } catch (OperatorCreationException e) {
                throw new CmpRequestorException(e);
            } catch (CMPException e) {
                throw new CmpRequestorException(e);
            }
        }
        else
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

    public X509Certificate getResponderCert() {
        return responderCert;
    }

    protected PKIHeader buildPKIHeader(ASN1OctetString tid)
    {
        return buildPKIHeader(false, tid, null);
    }

    protected PKIHeader buildPKIHeader(boolean addImplictConfirm,
            ASN1OctetString tid, InfoTypeAndValue generalInfo, InfoTypeAndValue... additionalGeneralInfos)
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

        if(addImplictConfirm)
        {
            hBuilder.setGeneralInfo(CmpUtil.getImplictConfirmGeneralInfo());
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
        synchronized (random) {
            random.nextBytes(tid);
        }
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

        ContentVerifierProvider verifierProvider = securityFactory.getContentVerifierProvider(
                responderCert);
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
        if(! response.hasProtection())
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
