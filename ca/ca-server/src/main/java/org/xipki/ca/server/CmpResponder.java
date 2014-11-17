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

package org.xipki.ca.server;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

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
import org.xipki.ca.api.CertBasedRequestorInfo;
import org.xipki.ca.api.CmpControl;
import org.xipki.ca.api.RequestorInfo;
import org.xipki.ca.common.cmp.CmpUtil;
import org.xipki.ca.common.cmp.ProtectionResult;
import org.xipki.ca.common.cmp.ProtectionVerificationResult;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.CustomObjectIdentifiers;
import org.xipki.common.SecurityUtil;
import org.xipki.common.LogUtil;
import org.xipki.common.ParamChecker;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

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

        Date messageTime = null;
        if(reqHeader.getMessageTime() != null)
        {
            try
            {
                messageTime = reqHeader.getMessageTime().getDate();
            } catch (ParseException e)
            {
                final String msg = "tid=" + tidStr + ": could not parse messageDate";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(msg), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(msg, e);
                messageTime = null;
            }
        }

        boolean cmdForCmpRespCert = false;
        int bodyType = message.getBody().getType();
        if(bodyType == PKIBody.TYPE_GEN_MSG)
        {
            GenMsgContent genMsgBody = (GenMsgContent) message.getBody().getContent();
            InfoTypeAndValue[] itvs = genMsgBody.toInfoTypeAndValueArray();

            if(itvs != null && itvs.length > 0)
            {
                for(InfoTypeAndValue itv : itvs)
                {
                    String itvType = itv.getInfoType().getId();
                    if(CustomObjectIdentifiers.id_cmp_getCmpResponderCert.equals(itvType))
                    {
                        cmdForCmpRespCert = true;
                        break;
                    }
                }
            }
        }

        boolean intentMe = checkRequestRecipient(reqHeader);

        if(intentMe == false && cmdForCmpRespCert == false)
        {
            LOG.warn("tid={}: I am not the intented recipient, but '{}'", tid, reqHeader.getRecipient());
            failureCode = PKIFailureInfo.badRequest;
            statusText = "I am not the intended recipient";
        }
        else if(messageTime == null)
        {
            if(cmpControl.isMessageTimeRequired())
            {
                failureCode = PKIFailureInfo.missingTimeStamp;
                statusText = "missing timestamp";
            }
        }
        else
        {
            long messageTimeBias = cmpControl.getMessageTimeBias();
            if(messageTimeBias < 0)
            {
                messageTimeBias *= -1;
            }

            long msgTimeMs = messageTime.getTime();
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
                final String msg = "tid=" + tidStr + ": error while verifying the signature";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(msg), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(msg, e);
                errorStatus = "Request has invalid signature based protection";
            }
        }
        else if(tlsClientCert != null)
        {
            boolean authorized = false;

            requestor = getRequestor(reqHeader);
            if(requestor != null)
            {
                if(tlsClientCert.equals(requestor.getCertificate().getCert()))
                {
                    authorized = true;
                }
            }

            if(authorized)
            {
                errorStatus = null;
            }
            else
            {
                LOG.warn("tid={}: not authorized requestor (TLS client {})",
                        tid, SecurityUtil.getRFC4519Name(tlsClientCert.getSubjectX500Principal()));
                errorStatus = "Requestor (TLS client certificate) is not authorized";
            }
        }
        else
        {
            errorStatus = "Request has no protection";
            requestor = null;
        }

        String username = null;
        if(cmdForCmpRespCert == false)
        {
            CmpUtf8Pairs keyvalues = CmpUtil.extract(reqHeader.getGeneralInfo());
            username = keyvalues == null ? null : keyvalues.getValue(CmpUtf8Pairs.KEY_USER);
            if(username != null)
            {
                if(username.indexOf('*') != -1 || username.indexOf('%') != -1)
                {
                    errorStatus = "user could not contains characters '*' and '%'";
                }
            }
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

        PKIMessage resp;
        if(cmdForCmpRespCert)
        {
            if(auditEvent != null)
            {
                auditEvent.addEventData(new AuditEventData("eventType", "GET_CMPRESPONDER"));
                auditEvent.addEventData(new AuditEventData("requestor", requestor.getCertificate().getSubject()));
            }

            InfoTypeAndValue itv = new InfoTypeAndValue(
                    new ASN1ObjectIdentifier(CustomObjectIdentifiers.id_cmp_getCmpResponderCert),
                    responder.getCertificateAsBCObject().toASN1Structure());
            GenRepContent genRepContent = new GenRepContent(itv);
            PKIBody respBody = new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);

            PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
                    reqHeader.getPvno().getValue().intValue(),
                    sender,
                    reqHeader.getSender());
            respHeader.setTransactionID(tid);
            resp = new PKIMessage(respHeader.build(), respBody);
        }
        else
        {
            resp = intern_processPKIMessage(requestor, username, tid, message, auditEvent);
        }

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
            final String message = "error while add protection to the PKI message";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);

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

    private boolean checkRequestRecipient(PKIHeader reqHeader)
    {
        GeneralName recipient = reqHeader.getRecipient();
        if(recipient == null)
        {
            return false;
        }

        if(sender.equals(recipient))
        {
            return true;
        }

        if(recipient.getTagNo() == GeneralName.directoryName)
        {
            X500Name x500Name = X500Name.getInstance(recipient.getName());
            String sortedName = canonicalizeSortedName(x500Name);
            if(sortedName.equals(this.c14nSenderName))
            {
                return true;
            }
        }

        return false;
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
        X500Principal x500Prin = requestor.getCertificate().getCert().getSubjectX500Principal();
        X500Name x500Name = X500Name.getInstance(x500Prin.getEncoded());
        String c14nName = canonicalizeSortedName(x500Name);
        this.authorizatedRequestors.put(c14nName, requestor);
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
        return SecurityUtil.getRFC4519Name(SecurityUtil.sortX509Name(name));
    }

}
