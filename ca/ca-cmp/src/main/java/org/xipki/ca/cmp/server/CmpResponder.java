/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.ca.cmp.server;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
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
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditStatus;
import org.xipki.ca.cmp.CmpUtil;
import org.xipki.ca.cmp.ProtectionResult;
import org.xipki.ca.cmp.ProtectionVerificationResult;
import org.xipki.ca.common.CertBasedRequestorInfo;
import org.xipki.ca.common.RequestorInfo;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public abstract class CmpResponder
{
    private static final Logger LOG = LoggerFactory.getLogger(CmpResponder.class);

    private final SecureRandom random = new SecureRandom();
    protected final ConcurrentContentSigner responder;
    protected final GeneralName sender;
    private final String c14nSenderName;

    private final Map<String, CertBasedRequestorInfo> authorizatedRequestors = new HashMap<>();

    protected final SecurityFactory securityFactory;

    public abstract boolean isCAInService();

    /**
     * @return never returns {@code null}.
     */
    protected abstract CmpControl getCmpControl();

    protected abstract PKIMessage intern_processPKIMessage(RequestorInfo requestor, String user,
            ASN1OctetString transactionId, GeneralPKIMessage pkiMessage, AuditEvent auditEvent);

    protected CmpResponder(ConcurrentContentSigner responder, SecurityFactory securityFactory)
    {
        ParamChecker.assertNotNull("responder", responder);
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        this.responder = responder;
        this.securityFactory = securityFactory;
        X500Name x500Name = X500Name.getInstance(responder.getCertificate().getSubjectX500Principal().getEncoded());
        this.sender = new GeneralName(x500Name);
        this.c14nSenderName = canonicalizeSortedName(x500Name);
    }

    public PKIMessage processPKIMessage(PKIMessage pkiMessage, X509Certificate tlsClientCert, AuditEvent auditEvent)
    {
        GeneralPKIMessage message = new GeneralPKIMessage(pkiMessage);

        PKIHeader reqHeader = message.getHeader();
        ASN1OctetString tid = reqHeader.getTransactionID();

        checkRequestRecipient(reqHeader);

        if(tid == null)
        {
            byte[] randomBytes = randomTransactionId();
            tid = new DEROctetString(randomBytes);
        }
        String tidStr = Hex.toHexString(tid.getOctets());
        if(auditEvent != null)
        {
            auditEvent.addEventData(new AuditEventData("tid", tidStr));
        }

        CmpControl cmpControl = getCmpControl();

        Integer failureCode = null;
        String statusText = null;

        DERGeneralizedTime messageTime = reqHeader.getMessageTime();

        if(messageTime == null)
        {
            if(cmpControl.isMessageTimeRequired())
            {
                failureCode = PKIFailureInfo.missingTimeStamp;
                statusText = "missing timestamp";
            }
        }
        else
        {
            try
            {
                long messageTimeBias = cmpControl.getMessageTimeBias();
                if(messageTimeBias < 0)
                {
                    messageTimeBias *= -1;
                }

                long msgTimeMs = messageTime.getDate().getTime();
                long currentTimeMs = System.currentTimeMillis();
                long bias = (msgTimeMs - currentTimeMs)/ 1000L;
                if(bias > messageTimeBias)
                {
                    failureCode = PKIFailureInfo.badTime;
                    statusText = "message time is in the future";
                }
                else if(bias * -1 > messageTimeBias)
                {
                    failureCode = PKIFailureInfo.badTime;
                    statusText = "message too old";
                }
            } catch (ParseException e)
            {
                failureCode = PKIFailureInfo.badRequest;
                statusText = "invalid message time format";
            }
        }

        if(failureCode != null)
        {
            if(auditEvent != null)
            {
                auditEvent.setLevel(AuditLevel.INFO);
                auditEvent.setStatus(AuditStatus.FAILED);
                auditEvent.addEventData(new AuditEventData("message", statusText));
            }
            return buildErrorPkiMessage(tid, reqHeader, failureCode, statusText);
        }

        boolean isProtected = message.hasProtection();
        CertBasedRequestorInfo requestor = null;

        String errorStatus;

        if(isProtected)
        {
            try
            {
                ProtectionVerificationResult verificationResult = verifyProtection(tidStr, message);
                ProtectionResult pr = verificationResult.getProtectionResult();
                switch(pr)
                {
                case VALID:
                    errorStatus = null;
                    break;
                case INVALID:
                    errorStatus = "Request is protected by signature but invalid";
                    break;
                case NOT_SIGNATURE_BASED:
                    errorStatus = "Request is not protected by signature";
                    break;
                case SENDER_NOT_AUTHORIZED:
                    errorStatus = "Request is protected by signature but the requestor is not authorized";
                    break;
                default:
                    throw new RuntimeException("Should not reach here");
                }
                requestor = (CertBasedRequestorInfo) verificationResult.getRequestor();
            } catch (Exception e)
            {
                LOG.error("tid=" + tidStr + ": error while verifying the signature: {}", e.getMessage());
                LOG.debug("tid=" + tidStr + ": error while verifying the signature", e);
                errorStatus = "Request has invalid signature based protection";
            }
        }
        else if(tlsClientCert != null)
        {
            boolean authorized = false;
            for(CertBasedRequestorInfo authorizatedRequestor : authorizatedRequestors.values())
            {
                if(tlsClientCert.equals(authorizatedRequestor.getCertificate().getCert()))
                {
                    requestor = authorizatedRequestor;
                    authorized = true;
                    break;
                }
            }
            if(authorized)
            {
                errorStatus = null;
            }
            else
            {
                LOG.warn("tid={}: not authorized requestor (TLS client {})",
                        tid, IoCertUtil.canonicalizeName(tlsClientCert.getSubjectX500Principal()));
                errorStatus = "Requestor (TLS client certificate) is not authorized";
            }

        }
        else
        {
            errorStatus = "Request has no protection";
            requestor = null;
        }

        if(errorStatus != null)
        {
            if(auditEvent != null)
            {
                auditEvent.setLevel(AuditLevel.INFO);
                auditEvent.setStatus(AuditStatus.FAILED);
                auditEvent.addEventData(new AuditEventData("message", errorStatus));
            }
            return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.badMessageCheck, errorStatus);
        }

        CmpUtf8Pairs keyvalues = CmpUtil.extract(reqHeader.getGeneralInfo());
        String username = keyvalues == null ? null : keyvalues.getValue(CmpUtf8Pairs.KEY_USER);

        PKIMessage resp = intern_processPKIMessage(requestor, username, tid, message, auditEvent);
        if(isProtected)
        {
            resp = addProtection(resp, auditEvent);
        }
        else
        {
            // protected by TLS connection
        }

        return resp;
    }

    protected byte[] randomTransactionId()
    {
        byte[] b = new byte[10];
           random.nextBytes(b);
        return  b;
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
        CertBasedRequestorInfo requestor = getRequestor(h);
        if(requestor == null)
        {
            LOG.warn("tid={}: not authorized requestor {}", tid, h.getSender());
            return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
        }

        ContentVerifierProvider verifierProvider = securityFactory.getContentVerifierProvider(
                requestor.getCertificate().getCert());
        if(verifierProvider == null)
        {
            LOG.warn("tid={}: not authorized requestor {}", tid, h.getSender());
            return new ProtectionVerificationResult(requestor, ProtectionResult.SENDER_NOT_AUTHORIZED);
        }

        boolean signatureValid = pMsg.verify(verifierProvider);
        return new ProtectionVerificationResult(requestor,
                signatureValid ? ProtectionResult.VALID : ProtectionResult.INVALID);
    }

    private PKIMessage addProtection(PKIMessage pkiMessage, AuditEvent auditEvent)
    {
        try
        {
            return CmpUtil.addProtection(pkiMessage, responder, sender, getCmpControl().isSendResponderCert());
        } catch (Exception e)
        {
            LOG.error("error while add protection to the PKI message: {}", e.getMessage());
            LOG.debug("error while add protection to the PKI message", e);

            PKIStatusInfo status = generateCmpRejectionStatus(
                    PKIFailureInfo.systemFailure, "could not sign the PKIMessage");
            PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, new ErrorMsgContent(status));

            if(auditEvent !=  null)
            {
                auditEvent.setLevel(AuditLevel.ERROR);
                auditEvent.setStatus(AuditStatus.ERROR);
                auditEvent.addEventData(new AuditEventData("message", "could not sign the PKIMessage"));
            }
            return new PKIMessage(pkiMessage.getHeader(), body);
        }
    }

    private void checkRequestRecipient(PKIHeader reqHeader)
    {
        ASN1OctetString tid = reqHeader.getTransactionID();
        GeneralName recipient = reqHeader.getRecipient();

        if(sender.equals(recipient))
        {
            return;
        }

        if(recipient.getTagNo() == GeneralName.directoryName)
        {
            X500Name x500Name = X500Name.getInstance(recipient.getName());
            String sortedName = canonicalizeSortedName(x500Name);
            if(sortedName.equals(this.c14nSenderName))
            {
                return;
            }
        }

        LOG.warn("tid={}: Unknown Recipient '{}'", tid, recipient);
    }

    protected PKIMessage buildErrorPkiMessage(ASN1OctetString tid,
            PKIHeader requestHeader,
            int failureCode,
            String statusText)
    {
        GeneralName respRecipient = requestHeader.getSender();

        PKIHeaderBuilder respHeader = new PKIHeaderBuilder(requestHeader.getPvno().getValue().intValue(),
                sender, respRecipient);
        respHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
        if(tid != null)
        {
            respHeader.setTransactionID(tid);
        }

        PKIStatusInfo status = generateCmpRejectionStatus(failureCode, statusText);
        ErrorMsgContent error = new ErrorMsgContent(status);
        PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, error);

        return new PKIMessage(respHeader.build(), body);
    }

    private CertBasedRequestorInfo getRequestor(PKIHeader reqHeader)
    {
        GeneralName requestSender = reqHeader.getSender();
        if(requestSender.getTagNo() != GeneralName.directoryName)
        {
            return null;
        }

        String c14nName = canonicalizeSortedName((X500Name) requestSender.getName());
        CertBasedRequestorInfo requestor = authorizatedRequestors.get(c14nName);
        if(requestor != null)
        {
            ASN1OctetString kid = reqHeader.getSenderKID();
            if(kid != null)
            {
                // TODO : check the kid
            }
        }

        return requestor;
    }

    protected PKIStatusInfo generateCmpRejectionStatus(Integer info, String errorMessage)
    {
        PKIFreeText statusMessage = (errorMessage == null) ? null : new PKIFreeText(errorMessage);
        PKIFailureInfo failureInfo = (info == null) ? null : new PKIFailureInfo(info);
        return new PKIStatusInfo(PKIStatus.rejection, statusMessage, failureInfo);
    }

    public void addAutorizatedRequestor(CertBasedRequestorInfo requestor)
    {
        this.authorizatedRequestors.put(requestor.getCertificate().getSubject(), requestor);
    }

    public X500Name getResponderName()
    {
        return sender == null ? null : (X500Name) sender.getName();
    }

    public X509Certificate getResponderCert()
    {
        return responder == null ? null : responder.getCertificate();
    }

    private static String canonicalizeSortedName(X500Name name)
    {
        return IoCertUtil.canonicalizeName(IoCertUtil.sortX509Name(name));
    }

}
