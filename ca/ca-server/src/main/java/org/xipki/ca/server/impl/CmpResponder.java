/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.ca.server.impl;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
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
import org.xipki.ca.api.RequestorInfo;
import org.xipki.ca.common.cmp.CmpUtil;
import org.xipki.ca.common.cmp.ProtectionResult;
import org.xipki.ca.common.cmp.ProtectionVerificationResult;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.LogUtil;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

abstract class CmpResponder
{
    private static final Logger LOG = LoggerFactory.getLogger(CmpResponder.class);

    private final SecureRandom random = new SecureRandom();
    protected abstract ConcurrentContentSigner getSigner();
    protected abstract GeneralName getSender();
    protected abstract boolean intendsMe(GeneralName requestRecipient);

    protected final SecurityFactory securityFactory;

    public abstract boolean isCAInService();

    /**
     * @return never returns {@code null}.
     */
    protected abstract CmpControl getCmpControl();

    protected abstract CmpRequestorInfo getRequestor(X500Name requestorSender);

    protected abstract PKIMessage intern_processPKIMessage(RequestorInfo requestor, String user,
            ASN1OctetString transactionId, GeneralPKIMessage pkiMessage, AuditEvent auditEvent);

    protected CmpResponder(SecurityFactory securityFactory)
    {
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        this.securityFactory = securityFactory;
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

        GeneralName recipient = reqHeader.getRecipient();
        boolean intentMe = (recipient == null) ? null : intendsMe(recipient);
        if(intentMe == false)
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
        CmpRequestorInfo requestor = null;

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
                requestor = (CmpRequestorInfo) verificationResult.getRequestor();
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
                if(tlsClientCert.equals(requestor.getCert().getCert()))
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
                LOG.warn("tid={}: not authorized requestor (TLS client '{}')",
                        tid, SecurityUtil.getRFC4519Name(tlsClientCert.getSubjectX500Principal()));
                errorStatus = "Requestor (TLS client certificate) is not authorized";
            }
        }
        else
        {
            errorStatus = "Request has no protection";
            requestor = null;
        }

        CmpUtf8Pairs keyvalues = CmpUtil.extract(reqHeader.getGeneralInfo());
        String username = keyvalues == null ? null : keyvalues.getValue(CmpUtf8Pairs.KEY_USER);
        if(username != null)
        {
            if(username.indexOf('*') != -1 || username.indexOf('%') != -1)
            {
                errorStatus = "user could not contains characters '*' and '%'";
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
        CmpRequestorInfo requestor = getRequestor(h);
        if(requestor == null)
        {
            LOG.warn("tid={}: not authorized requestor '{}'", tid, h.getSender());
            return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
        }

        ContentVerifierProvider verifierProvider = securityFactory.getContentVerifierProvider(
                requestor.getCert().getCert());
        if(verifierProvider == null)
        {
            LOG.warn("tid={}: not authorized requestor '{}'", tid, h.getSender());
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
            return CmpUtil.addProtection(pkiMessage, getSigner(), getSender(), getCmpControl().isSendResponderCert());
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

    protected PKIMessage buildErrorPkiMessage(ASN1OctetString tid,
            PKIHeader requestHeader,
            int failureCode,
            String statusText)
    {
        GeneralName respRecipient = requestHeader.getSender();

        PKIHeaderBuilder respHeader = new PKIHeaderBuilder(requestHeader.getPvno().getValue().intValue(),
                getSender(), respRecipient);
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

    private CmpRequestorInfo getRequestor(PKIHeader reqHeader)
    {
        GeneralName requestSender = reqHeader.getSender();
        if(requestSender.getTagNo() != GeneralName.directoryName)
        {
            return null;
        }

        return getRequestor((X500Name) requestSender.getName());
    }

    protected PKIStatusInfo generateCmpRejectionStatus(Integer info, String errorMessage)
    {
        PKIFreeText statusMessage = (errorMessage == null) ? null : new PKIFreeText(errorMessage);
        PKIFailureInfo failureInfo = (info == null) ? null : new PKIFailureInfo(info);
        return new PKIStatusInfo(PKIStatus.rejection, statusMessage, failureInfo);
    }

    public X500Name getResponderName()
    {
        GeneralName sender = getSender();
        return sender == null ? null : (X500Name) sender.getName();
    }

    public X509Certificate getResponderCert()
    {
        ConcurrentContentSigner signer = getSigner();
        return signer == null ? null : signer.getCertificate();
    }

}
