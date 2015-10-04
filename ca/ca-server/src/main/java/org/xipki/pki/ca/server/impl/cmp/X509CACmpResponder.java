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

package org.xipki.pki.ca.server.impl.cmp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
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
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContentBuilder;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditChildEvent;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditStatus;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.pki.ca.api.InsuffientPermissionException;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.RequestorInfo;
import org.xipki.pki.ca.api.publisher.X509CertificateInfo;
import org.xipki.pki.ca.common.cmp.CmpUtf8Pairs;
import org.xipki.pki.ca.common.cmp.CmpUtil;
import org.xipki.pki.ca.server.impl.CAManagerImpl;
import org.xipki.pki.ca.server.impl.X509CA;
import org.xipki.pki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CAStatus;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControl;
import org.xipki.pki.ca.server.mgmt.api.Permission;
import org.xipki.security.api.CRLReason;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.ObjectIdentifiers;
import org.xipki.security.api.XipkiCmpConstants;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class X509CACmpResponder extends CmpResponder {
    private static final Set<String> knownGenMsgIds = new HashSet<>();

    private static final Logger LOG = LoggerFactory.getLogger(X509CACmpResponder.class);

    private final DateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd-HH:mm:ss.SSSz");
    private final PendingCertificatePool pendingCertPool;

    private final String caName;
    private final CAManagerImpl caManager;

    static {
        knownGenMsgIds.add(CMPObjectIdentifiers.it_currentCRL.getId());
        knownGenMsgIds.add(ObjectIdentifiers.id_xipki_cm_cmpGenmsg.getId());
    }

    public X509CACmpResponder(
            final CAManagerImpl caManager,
            final String caName) {
        super(caManager.getSecurityFactory());

        this.caManager = caManager;
        this.pendingCertPool = new PendingCertificatePool();
        this.caName = caName;

        PendingPoolCleaner pendingPoolCleaner = new PendingPoolCleaner();
        caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
            pendingPoolCleaner, 10, 10, TimeUnit.MINUTES);
    }

    public X509CA getCA() {
        try {
            return caManager.getX509CA(caName);
        } catch (CAMgmtException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    @Override
    public boolean isInService() {
        if (!super.isInService()) {
            return false;
        }

        if (CAStatus.ACTIVE != getCA().getCAInfo().getStatus()) {
            return false;
        }

        return true;
    }

    public HealthCheckResult healthCheck() {
        HealthCheckResult result = getCA().healthCheck();

        boolean healthy = result.isHealthy();

        boolean responderHealthy;
        try {
            responderHealthy = caManager.getCmpResponderWrapper(
                    getResponderName()).getSigner().isHealthy();
        } catch (InvalidConfException e) {
            responderHealthy = false;
        }
        healthy &= responderHealthy;

        HealthCheckResult responderHealth = new HealthCheckResult("Responder");
        responderHealth.setHealthy(responderHealthy);
        result.addChildCheck(responderHealth);

        result.setHealthy(healthy);
        return result;
    }

    public String getResponderName()
    throws InvalidConfException {
        String name = getCA().getCAInfo().getResponderName();
        if (name == null) {
            throw new InvalidConfException("No responder is configured for CA " + caName);
        }
        return name;
    }

    @Override
    protected PKIMessage intern_processPKIMessage(
            final RequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final GeneralPKIMessage message,
            final AuditEvent auditEvent)
    throws InvalidConfException {
        if (!(requestor instanceof CmpRequestorInfo)) {
            throw new IllegalArgumentException(
                    "unknown requestor type " + requestor.getClass().getName());
        }

        CmpRequestorInfo _requestor = (CmpRequestorInfo) requestor;
        if (_requestor != null && auditEvent != null) {
            auditEvent.addEventData(new AuditEventData("requestor",
                    _requestor.getCert().getSubject()));
        }

        PKIHeader reqHeader = message.getHeader();
        PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
                reqHeader.getPvno().getValue().intValue(),
                getSender(),
                reqHeader.getSender());
        respHeader.setTransactionID(tid);

        PKIBody respBody;
        PKIBody reqBody = message.getBody();
        final int type = reqBody.getType();

        CmpControl cmpControl = getCmpControl();

        try {
            switch (type) {
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
            case PKIBody.TYPE_P10_CERT_REQ:
            case PKIBody.TYPE_CROSS_CERT_REQ: {
                respBody = cmpEnrollCert(respHeader, cmpControl, reqHeader, reqBody,
                        _requestor, user, tid, auditEvent);
                break;
            }
            case PKIBody.TYPE_CERT_CONFIRM: {
                addAutitEventType(auditEvent, "CERT_CONFIRM");
                CertConfirmContent certConf = (CertConfirmContent) reqBody.getContent();
                respBody = confirmCertificates(tid, certConf);
                break;
            }
            case PKIBody.TYPE_REVOCATION_REQ: {
                respBody = cmpRevokeOrUnrevokeOrRemoveCertificates(respHeader, cmpControl,
                        reqHeader, reqBody,
                        _requestor, user, tid, auditEvent);
                break;
            }
            case PKIBody.TYPE_CONFIRM: {
                addAutitEventType(auditEvent, "CONFIRM");
                respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
            }
            case PKIBody.TYPE_ERROR: {
                addAutitEventType(auditEvent, "ERROR");
                revokePendingCertificates(tid);
                respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
                break;
            }
            case PKIBody.TYPE_GEN_MSG: {
                respBody = cmpGeneralMsg(respHeader, cmpControl, reqHeader, reqBody, _requestor,
                        user, tid, auditEvent);
                break;
            }
            default: {
                addAutitEventType(auditEvent, "PKIBody." + type);
                respBody = createErrorMsgPKIBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                        "unsupported type " + type);
                break;
            }
            } // end switch (type)
        } catch (InsuffientPermissionException e) {
            ErrorMsgContent emc = new ErrorMsgContent(
                    new PKIStatusInfo(PKIStatus.rejection,
                            new PKIFreeText(e.getMessage()),
                            new PKIFailureInfo(PKIFailureInfo.notAuthorized)));

            respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
        }

        if (auditEvent != null) {
            if (respBody.getType() == PKIBody.TYPE_ERROR) {
                ErrorMsgContent errorMsgContent = (ErrorMsgContent) respBody.getContent();

                AuditStatus auditStatus = AuditStatus.FAILED;
                org.xipki.pki.ca.common.cmp.PKIStatusInfo pkiStatus =
                        new org.xipki.pki.ca.common.cmp.PKIStatusInfo(
                                errorMsgContent.getPKIStatusInfo());

                if (pkiStatus.getPkiFailureInfo() == PKIFailureInfo.systemFailure) {
                    auditStatus = AuditStatus.FAILED;
                }
                auditEvent.setStatus(auditStatus);

                String statusString = pkiStatus.getStatusMessage();
                if (statusString != null) {
                    auditEvent.addEventData(new AuditEventData("message", statusString));
                }
            } else if (auditEvent.getStatus() == null) {
                auditEvent.setStatus(AuditStatus.SUCCESSFUL);
            }
        }

        return new PKIMessage(respHeader.build(), respBody);
    }

    /**
     * handle the PKI body with the choice {@code cr}
     *
     */
    private PKIBody processCr(
            final CmpRequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final PKIHeader reqHeader,
            final CertReqMessages cr,
            final long confirmWaitTime,
            final boolean sendCaCert,
            final AuditEvent auditEvent)
    throws InsuffientPermissionException {
        CertRepMessage repMessage = processCertReqMessages(requestor, user, tid, reqHeader, cr,
                false, confirmWaitTime, sendCaCert, auditEvent);
        return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
    }

    private PKIBody processKur(
            final CmpRequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final PKIHeader reqHeader,
            final CertReqMessages kur,
            final long confirmWaitTime,
            final boolean sendCaCert,
            final AuditEvent auditEvent)
    throws InsuffientPermissionException {
        CertRepMessage repMessage = processCertReqMessages(requestor, user, tid, reqHeader, kur,
                true, confirmWaitTime, sendCaCert, auditEvent);
        return new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, repMessage);
    }

    /**
     * handle the PKI body with the choice {@code cr}
     *
     */
    private PKIBody processCcp(
            final CmpRequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final PKIHeader reqHeader,
            final CertReqMessages cr,
            final long confirmWaitTime,
            final boolean sendCaCert,
            final AuditEvent auditEvent)
    throws InsuffientPermissionException {
        CertRepMessage repMessage = processCertReqMessages(requestor, user, tid, reqHeader, cr,
                false, confirmWaitTime, sendCaCert, auditEvent);
        return new PKIBody(PKIBody.TYPE_CROSS_CERT_REP, repMessage);
    }

    private CertRepMessage processCertReqMessages(
            final CmpRequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final PKIHeader reqHeader,
            final CertReqMessages kur,
            final boolean keyUpdate,
            final long confirmWaitTime,
            final boolean sendCaCert,
            final AuditEvent auditEvent)
    throws InsuffientPermissionException {
        CmpRequestorInfo _requestor = (CmpRequestorInfo) requestor;

        CertReqMsg[] certReqMsgs = kur.toCertReqMsgArray();
        CertResponse[] certResponses = new CertResponse[certReqMsgs.length];

        for (int i = 0; i < certReqMsgs.length; i++) {
            AuditChildEvent childAuditEvent = null;
            if (auditEvent != null) {
                childAuditEvent = new AuditChildEvent();
                auditEvent.addChildAuditEvent(childAuditEvent);
            }

            CertReqMsg reqMsg = certReqMsgs[i];
            CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);
            ASN1Integer certReqId = reqMsg.getCertReq().getCertReqId();
            if (childAuditEvent != null) {
                childAuditEvent.addEventData(
                        new AuditEventData("certReqId", certReqId.getPositiveValue().toString()));
            }

            if (!req.hasProofOfPossession()) {
                PKIStatusInfo status = generateCmpRejectionStatus(PKIFailureInfo.badPOP, null);
                certResponses[i] = new CertResponse(certReqId, status);

                if (childAuditEvent != null) {
                    childAuditEvent.setStatus(AuditStatus.FAILED);
                    childAuditEvent.addEventData(new AuditEventData("message", "no POP"));
                }
                continue;
            }

            if (!verifyPOP(req, _requestor.isRA())) {
                LOG.warn("could not validate POP for requst {}", certReqId.getValue());
                PKIStatusInfo status = generateCmpRejectionStatus(PKIFailureInfo.badPOP, null);
                certResponses[i] = new CertResponse(certReqId, status);
                if (childAuditEvent != null) {
                    childAuditEvent.setStatus(AuditStatus.FAILED);
                    childAuditEvent.addEventData(new AuditEventData("message", "invalid POP"));
                }
                continue;
            }

            CertTemplate certTemp = req.getCertTemplate();
            Extensions extensions = certTemp.getExtensions();
            X500Name subject = certTemp.getSubject();
            SubjectPublicKeyInfo publicKeyInfo = certTemp.getPublicKey();
            OptionalValidity validity = certTemp.getValidity();

            try {
                CmpUtf8Pairs keyvalues  = CmpUtil.extract(reqMsg.getRegInfo());
                String certprofileName = (keyvalues == null)
                        ? null
                        : keyvalues.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);
                if (certprofileName == null) {
                    throw new CMPException("no certificate profile is specified");
                }

                if (childAuditEvent != null) {
                    childAuditEvent.addEventData(
                            new AuditEventData("certprofile", certprofileName));
                }

                checkPermission(_requestor, certprofileName);
                certResponses[i] = generateCertificate(_requestor, user, tid, certReqId,
                        subject, publicKeyInfo, validity, extensions,
                        certprofileName, keyUpdate, confirmWaitTime, childAuditEvent);
            } catch (CMPException e) {
                final String message = "generateCertificate";
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);

                certResponses[i] = new CertResponse(certReqId,
                        generateCmpRejectionStatus(PKIFailureInfo.badCertTemplate, e.getMessage()));

                if (childAuditEvent != null) {
                    childAuditEvent.setStatus(AuditStatus.FAILED);
                    childAuditEvent.addEventData(new AuditEventData("message", "badCertTemplate"));
                }
            } // end try
        } // end for

        CMPCertificate[] caPubs = sendCaCert
                ? new CMPCertificate[]{getCA().getCAInfo().getCertInCMPFormat()}
                : null;
        return new CertRepMessage(caPubs, certResponses);
    }

    /**
     * handle the PKI body with the choice {@code p10cr}<br/>
     * Since it is not possible to add attribute to the PKCS#10 request, the certificate profile
     * must be specified in the attribute regInfo-utf8Pairs (1.3.6.1.5.5.7.5.2.1) within
     * PKIHeader.generalInfo
     *
     */
    private PKIBody processP10cr(
            final CmpRequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final PKIHeader reqHeader,
            final CertificationRequest p10cr,
            final long confirmWaitTime,
            final boolean sendCaCert,
            final AuditEvent auditEvent)
    throws InsuffientPermissionException {
        // verify the POP first
        CertResponse certResp;
        ASN1Integer certReqId = new ASN1Integer(-1);

        AuditChildEvent childAuditEvent = null;
        if (auditEvent != null) {
            childAuditEvent = new AuditChildEvent();
            auditEvent.addChildAuditEvent(childAuditEvent);
        }

        if (!securityFactory.verifyPOPO(p10cr)) {
            LOG.warn("could not validate POP for the pkcs#10 requst");
            PKIStatusInfo status = generateCmpRejectionStatus(PKIFailureInfo.badPOP, null);
            certResp = new CertResponse(certReqId, status);
            if (childAuditEvent != null) {
                childAuditEvent.setStatus(AuditStatus.FAILED);
                childAuditEvent.addEventData(new AuditEventData("message", "invalid POP"));
            }
        } else {
            CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
            Extensions extensions = X509Util.getExtensions(certTemp);

            X500Name subject = certTemp.getSubject();
            if (childAuditEvent != null) {
                childAuditEvent.addEventData(
                        new AuditEventData("req-subject", X509Util.getRFC4519Name(subject)));
            }

            SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

            try {
                CmpUtf8Pairs keyvalues = CmpUtil.extract(reqHeader.getGeneralInfo());
                String certprofileName = (keyvalues == null)
                        ? null
                        : keyvalues.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);
                if (certprofileName == null) {
                    throw new CMPException("no certificate profile is specified");
                }

                if (childAuditEvent != null) {
                    childAuditEvent.addEventData(
                            new AuditEventData("certprofile", certprofileName));
                }

                checkPermission(requestor, certprofileName);

                certResp = generateCertificate(requestor, user, tid, certReqId,
                    subject, publicKeyInfo, null, extensions, certprofileName,
                    false, confirmWaitTime, childAuditEvent);
            } catch (CMPException e) {
                certResp = new CertResponse(certReqId,
                        generateCmpRejectionStatus(PKIFailureInfo.badCertTemplate,
                        e.getMessage()));
                if (childAuditEvent != null) {
                    childAuditEvent.setStatus(AuditStatus.FAILED);
                    childAuditEvent.addEventData(new AuditEventData("message", "badCertTemplate"));
                }
            } // end try
        }

        CMPCertificate[] caPubs = sendCaCert
                ? new CMPCertificate[]{getCA().getCAInfo().getCertInCMPFormat()}
                : null;
        CertRepMessage repMessage = new CertRepMessage(caPubs, new CertResponse[]{certResp});

        return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
    }

    private CertResponse generateCertificate(
            final CmpRequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final ASN1Integer certReqId,
            final X500Name subject,
            final SubjectPublicKeyInfo publicKeyInfo,
            final OptionalValidity validity,
            final Extensions extensions,
            final String certprofileName,
            final boolean keyUpdate,
            final long confirmWaitTime,
            final AuditChildEvent childAuditEvent)
    throws InsuffientPermissionException {
        checkPermission(requestor, certprofileName);

        Date notBefore = null;
        Date notAfter = null;
        if (validity != null) {
            Time t = validity.getNotBefore();
            if (t != null) {
                notBefore = t.getDate();
            }
            t = validity.getNotAfter();
            if (t != null) {
                notAfter = t.getDate();
            }
        }

        try {
            X509CA ca = getCA();
            X509CertificateInfo certInfo;
            if (keyUpdate) {
                certInfo = ca.regenerateCertificate(requestor.isRA(), requestor,
                        certprofileName, user,
                        subject, publicKeyInfo,
                        notBefore, notAfter, extensions, RequestType.CMP, tid.getOctets());
            } else {
                certInfo = ca.generateCertificate(requestor.isRA(), requestor, certprofileName,
                        user, subject, publicKeyInfo,
                        notBefore, notAfter, extensions, RequestType.CMP, tid.getOctets());
            }
            certInfo.setRequestor(requestor);
            certInfo.setUser(user);

            if (childAuditEvent != null) {
                childAuditEvent.addEventData(new AuditEventData("req-subject",
                        certInfo.getCert().getSubject()));
            }

            pendingCertPool.addCertificate(tid.getOctets(), certReqId.getPositiveValue(),
                    certInfo, System.currentTimeMillis() + confirmWaitTime);
            String warningMsg = certInfo.getWarningMessage();

            PKIStatusInfo statusInfo;
            if (StringUtil.isBlank(warningMsg)) {
                if (certInfo.isAlreadyIssued()) {
                    statusInfo = new PKIStatusInfo(PKIStatus.grantedWithMods,
                            new PKIFreeText("ALREADY_ISSUED"));
                } else {
                    statusInfo = new PKIStatusInfo(PKIStatus.granted);
                }
            } else {
                statusInfo = new PKIStatusInfo(PKIStatus.grantedWithMods,
                        new PKIFreeText(warningMsg));
            }

            if (childAuditEvent != null) {
                childAuditEvent.setStatus(AuditStatus.SUCCESSFUL);
            }

            CertOrEncCert cec = new CertOrEncCert(
                    CMPCertificate.getInstance(
                            certInfo.getCert().getEncodedCert()));
            CertifiedKeyPair kp = new CertifiedKeyPair(cec);
            CertResponse certResp = new CertResponse(certReqId, statusInfo, kp, null);
            return certResp;
        } catch (OperationException e) {
            ErrorCode code = e.getErrorCode();
            LOG.warn("generate certificate, OperationException: code={}, message={}",
                    code.name(), e.getErrorMessage());

            String auditMessage;

            int failureInfo;
            switch (code) {
            case ALREADY_ISSUED:
                failureInfo = PKIFailureInfo.badRequest;
                auditMessage = "ALREADY_ISSUED";
                break;
            case BAD_CERT_TEMPLATE:
                failureInfo = PKIFailureInfo.badCertTemplate;
                auditMessage = "BAD_CERT_TEMPLATE";
                break;
            case BAD_REQUEST:
                failureInfo = PKIFailureInfo.badRequest;
                auditMessage = "BAD_REQUEST";
            case CERT_REVOKED:
                failureInfo = PKIFailureInfo.certRevoked;
                auditMessage = "CERT_REVOKED";
                break;
            case CRL_FAILURE:
                failureInfo = PKIFailureInfo.systemFailure;
                auditMessage = "CRL_FAILURE";
                break;
            case DATABASE_FAILURE:
                failureInfo = PKIFailureInfo.systemFailure;
                auditMessage = "DATABASE_FAILURE";
                break;
            case NOT_PERMITTED:
                failureInfo = PKIFailureInfo.notAuthorized;
                auditMessage = "NOT_PERMITTED";
                break;
            case INSUFFICIENT_PERMISSION:
                failureInfo = PKIFailureInfo.notAuthorized;
                auditMessage = "INSUFFICIENT_PERMISSION";
                break;
            case INVALID_EXTENSION:
                failureInfo = PKIFailureInfo.systemFailure;
                auditMessage = "INVALID_EXTENSION";
                break;
            case SYSTEM_FAILURE:
                failureInfo = PKIFailureInfo.systemFailure;
                auditMessage = "System_Failure";
                break;
            case SYSTEM_UNAVAILABLE:
                failureInfo = PKIFailureInfo.systemUnavail;
                auditMessage = "System_Unavailable";
                break;
            case UNKNOWN_CERT:
                failureInfo = PKIFailureInfo.badCertId;
                auditMessage = "UNKNOWN_CERT";
                break;
            case UNKNOWN_CERT_PROFILE:
                failureInfo = PKIFailureInfo.badCertTemplate;
                auditMessage = "UNKNOWN_CERT_PROFILE";
                break;
            default:
                failureInfo = PKIFailureInfo.systemFailure;
                auditMessage = "InternalErrorCode " + e.getErrorCode();
                break;
            } // end switch (code)

            if (childAuditEvent != null) {
                childAuditEvent.setStatus(AuditStatus.FAILED);
                childAuditEvent.addEventData(new AuditEventData("message", auditMessage));
            }

            String errorMessage;
            switch (code) {
            case DATABASE_FAILURE:
            case SYSTEM_FAILURE:
                errorMessage = code.name();
                break;
            default:
                errorMessage = code.name() + ": " + e.getErrorMessage();
                break;
            } // end switch code
            PKIStatusInfo status = generateCmpRejectionStatus(failureInfo, errorMessage);
            return new CertResponse(certReqId, status);
        }
    }

    private PKIBody revokeOrUnrevokeOrRemoveCertificates(
            final RevReqContent rr,
            final AuditEvent auditEvent,
            final Permission permission) {
        RevDetails[] revContent = rr.toRevDetailsArray();

        RevRepContentBuilder repContentBuilder = new RevRepContentBuilder();

        final int n = revContent.length;
        // test the reques
        for (int i = 0; i < n; i++) {
            RevDetails revDetails = revContent[i];

            CertTemplate certDetails = revDetails.getCertDetails();
            X500Name issuer = certDetails.getIssuer();
            ASN1Integer serialNumber = certDetails.getSerialNumber();

            try {
                X500Name caSubject = getCA().getCAInfo().getCertificate().getSubjectAsX500Name();

                if (issuer == null) {
                    return createErrorMsgPKIBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate,
                            "issuer is not present");
                } else if (!issuer.equals(caSubject)) {
                    return createErrorMsgPKIBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate,
                            "issuer not targets at the CA");
                } else if (serialNumber == null) {
                    return createErrorMsgPKIBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate,
                            "serialNumber is not present");
                } else if (certDetails.getSigningAlg() != null
                        || certDetails.getValidity() != null
                        || certDetails.getSubject() != null
                        || certDetails.getPublicKey() != null
                        || certDetails.getIssuerUID() != null
                        || certDetails.getSubjectUID() != null
                        || certDetails.getExtensions() != null) {
                    return createErrorMsgPKIBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate,
                            "only version, issuer and serialNumber in RevDetails.certDetails are "
                            + "allowed, but more is specified");
                }
            } catch (IllegalArgumentException e) {
                return createErrorMsgPKIBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                        "the request is not invalid");
            }
        }

        for (int i = 0; i < n; i++) {
            AuditChildEvent childAuditEvent = null;
            if (auditEvent != null) {
                childAuditEvent = new AuditChildEvent();
                auditEvent.addChildAuditEvent(childAuditEvent);
            }

            RevDetails revDetails = revContent[i];

            CertTemplate certDetails = revDetails.getCertDetails();
            ASN1Integer serialNumber = certDetails.getSerialNumber();
            // serialNumber is not null due to the check in the previous for-block.

            X500Name caSubject = getCA().getCAInfo().getCertificate().getSubjectAsX500Name();
            BigInteger snBigInt = serialNumber.getPositiveValue();
            CertId certId = new CertId(new GeneralName(caSubject), serialNumber);

            if (childAuditEvent != null) {
                AuditEventData eventData = new AuditEventData("serialNumber", snBigInt.toString());
                childAuditEvent.addEventData(eventData);
            }

            PKIStatusInfo status;

            try {
                Object returnedObj = null;
                X509CA ca = getCA();
                if (Permission.UNREVOKE_CERT == permission) {
                    // unrevoke
                    returnedObj = ca.unrevokeCertificate(snBigInt);
                } else if (Permission.REMOVE_CERT == permission) {
                    // remove
                    returnedObj = ca.removeCertificate(snBigInt);
                } else {
                    // revoke
                    Date invalidityDate = null;
                    CRLReason reason = null;

                    Extensions crlDetails = revDetails.getCrlEntryDetails();
                    if (crlDetails != null) {
                        ASN1ObjectIdentifier extId = Extension.reasonCode;
                        ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
                        if (extValue != null) {
                            int reasonCode = ((ASN1Enumerated) extValue).getValue().intValue();
                            reason = CRLReason.forReasonCode(reasonCode);
                        }

                        extId = Extension.invalidityDate;
                        extValue = crlDetails.getExtensionParsedValue(extId);
                        if (extValue != null) {
                            try {
                                invalidityDate = ((ASN1GeneralizedTime) extValue).getDate();
                            } catch (ParseException e) {
                                throw new OperationException(ErrorCode.INVALID_EXTENSION,
                                        "invalid extension " + extId.getId());
                            }
                        }
                    } // end if (crlDetails)

                    if (reason == null) {
                        reason = CRLReason.UNSPECIFIED;
                    }

                    if (childAuditEvent != null) {
                        childAuditEvent.addEventData(
                                new AuditEventData("reason", reason.getDescription()));
                        if (invalidityDate != null) {
                            String value;
                            synchronized (dateFormat) {
                                value = dateFormat.format(invalidityDate);
                            }
                            childAuditEvent.addEventData(
                                    new AuditEventData("invalidityDate", value));
                        }
                    }

                    returnedObj = ca.revokeCertificate(snBigInt, reason, invalidityDate);
                } // end if (permission)

                if (returnedObj == null) {
                    throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
                }

                status = new PKIStatusInfo(PKIStatus.granted);
                if (childAuditEvent != null) {
                    childAuditEvent.setStatus(AuditStatus.SUCCESSFUL);
                }
            } catch (OperationException e) {
                ErrorCode code = e.getErrorCode();
                LOG.warn("{} certificate, OperationException: code={}, message={}",
                        new Object[]{permission.name(), code.name(), e.getErrorMessage()});

                String auditMessage;

                int failureInfo;
                switch (code) {
                case BAD_REQUEST:
                    failureInfo = PKIFailureInfo.badRequest;
                    auditMessage = "BAD_REQUEST";
                    break;
                case CERT_REVOKED:
                    failureInfo = PKIFailureInfo.certRevoked;
                    auditMessage = "CERT_REVOKED";
                    break;
                case CERT_UNREVOKED:
                    failureInfo = PKIFailureInfo.notAuthorized;
                    auditMessage = "CERT_UNREVOKED";
                    break;
                case DATABASE_FAILURE:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditMessage = "DATABASE_FAILURE";
                    break;
                case INVALID_EXTENSION:
                    failureInfo = PKIFailureInfo.unacceptedExtension;
                    auditMessage = "INVALID_EXTENSION";
                    break;
                case INSUFFICIENT_PERMISSION:
                    failureInfo = PKIFailureInfo.notAuthorized;
                    auditMessage = "INSUFFICIENT_PERMISSION";
                    break;
                case NOT_PERMITTED:
                    failureInfo = PKIFailureInfo.notAuthorized;
                    auditMessage = "NOT_PERMITTED";
                    break;
                case SYSTEM_FAILURE:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditMessage = "System_Failure";
                    break;
                case SYSTEM_UNAVAILABLE:
                    failureInfo = PKIFailureInfo.systemUnavail;
                    auditMessage = "System_Unavailable";
                    break;
                case UNKNOWN_CERT:
                    failureInfo = PKIFailureInfo.badCertId;
                    auditMessage = "UNKNOWN_CERT";
                    break;
                default:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditMessage = "InternalErrorCode " + e.getErrorCode();
                    break;
                } // end switch (code)

                if (childAuditEvent != null) {
                    childAuditEvent.setStatus(AuditStatus.FAILED);
                    childAuditEvent.addEventData(new AuditEventData("message", auditMessage));
                }

                String errorMessage;
                switch (code) {
                case DATABASE_FAILURE:
                case SYSTEM_FAILURE:
                    errorMessage = code.name();
                    break;
                default:
                    errorMessage = code.name() + ": " + e.getErrorMessage();
                    break;
                } // end switch (code)

                status = generateCmpRejectionStatus(failureInfo, errorMessage);
            } // end try

            repContentBuilder.add(status, certId);
        } // end for

        return new PKIBody(PKIBody.TYPE_REVOCATION_REP, repContentBuilder.build());
    }

    private PKIBody confirmCertificates(
            final ASN1OctetString transactionId,
            final CertConfirmContent certConf) {
        CertStatus[] certStatuses = certConf.toCertStatusArray();

        boolean successful = true;
        for (CertStatus certStatus : certStatuses) {
            ASN1Integer certReqId = certStatus.getCertReqId();
            byte[] certHash = certStatus.getCertHash().getOctets();
            X509CertificateInfo certInfo = pendingCertPool.removeCertificate(
                    transactionId.getOctets(), certReqId.getPositiveValue(), certHash);
            if (certInfo == null) {
                LOG.warn("no cert under transactionId={}, certReqId={} and certHash=0X{}",
                        new Object[]{transactionId, certReqId.getPositiveValue(),
                                Hex.toHexString(certHash)});
                continue;
            }

            PKIStatusInfo statusInfo = certStatus.getStatusInfo();
            boolean accept = true;
            if (statusInfo != null) {
                int status = statusInfo.getStatus().intValue();
                if (PKIStatus.GRANTED != status && PKIStatus.GRANTED_WITH_MODS != status) {
                    accept = false;
                }
            }

            if (accept) {
                continue;
            }

            BigInteger serialNumber = certInfo.getCert().getCert().getSerialNumber();
            X509CA ca = getCA();
            try {
                ca.revokeCertificate(serialNumber, CRLReason.CESSATION_OF_OPERATION, new Date());
            } catch (OperationException e) {
                final String msg = "could not revoke certificate ca=" + ca.getCAInfo().getName()
                        + " serialNumber=" + serialNumber;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(msg), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(msg, e);
            }

            successful = false;
        }

        // all other certificates should be revoked
        if (revokePendingCertificates(transactionId)) {
            successful = false;
        }

        if (successful) {
            return new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
        }

        ErrorMsgContent emc = new ErrorMsgContent(
                new PKIStatusInfo(PKIStatus.rejection, null,
                        new PKIFailureInfo(PKIFailureInfo.systemFailure)));

        return new PKIBody(PKIBody.TYPE_ERROR, emc);
    }

    private boolean revokePendingCertificates(
            final ASN1OctetString transactionId) {
        Set<X509CertificateInfo> remainingCerts = pendingCertPool.removeCertificates(
                transactionId.getOctets());

        if (CollectionUtil.isEmpty(remainingCerts)) {
            return true;
        }

        boolean successful = true;
        Date invalidityDate = new Date();
        X509CA ca = getCA();
        for (X509CertificateInfo remainingCert : remainingCerts) {
            try {
                ca.revokeCertificate(remainingCert.getCert().getCert().getSerialNumber(),
                    CRLReason.CESSATION_OF_OPERATION, invalidityDate);
            } catch (OperationException e) {
                successful = false;
            }
        }

        return successful;
    }

    private boolean verifyPOP(
            final CertificateRequestMessage certRequest,
            final boolean allowRAPopo) {
        int popType = certRequest.getProofOfPossessionType();
        if (popType == CertificateRequestMessage.popRaVerified && allowRAPopo) {
            return true;
        }

        if (popType != CertificateRequestMessage.popSigningKey) {
            LOG.error("unsupported POP type: " + popType);
            return false;
        }

        try {
            PublicKey publicKey = securityFactory.generatePublicKey(
                    certRequest.getCertTemplate().getPublicKey());
            ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(publicKey);
            return certRequest.isValidSigningKeyPOP(cvp);
        } catch (InvalidKeyException | IllegalStateException | CRMFException e) {
            final String message = "verifyPOP";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }
        return false;
    }

    @Override
    protected CmpControl getCmpControl() {
        X509CA ca = getCA();
        if (ca != null) {
            String name = ca.getCAInfo().getCmpControlName();
            if (name != null) {
                return caManager.getCmpControlObject(name);
            }
        }

        throw new IllegalStateException(
                "should not happen, no CMP control is defined for CA " + caName);
    }

    private class PendingPoolCleaner implements Runnable {
        @Override
        public void run() {
            Set<X509CertificateInfo> remainingCerts =
                    pendingCertPool.removeConfirmTimeoutedCertificates();

            if (CollectionUtil.isEmpty(remainingCerts)) {
                return;
            }

            Date invalidityDate = new Date();
            X509CA ca = getCA();
            for (X509CertificateInfo remainingCert : remainingCerts) {
                try {
                    ca.revokeCertificate(remainingCert.getCert().getCert().getSerialNumber(),
                        CRLReason.CESSATION_OF_OPERATION, invalidityDate);
                } catch (Throwable t) {
                }
            }
        }
    }

    private void checkPermission(
            final CmpRequestorInfo requestor,
            final String certprofile)
    throws InsuffientPermissionException {
        Set<String> profiles = requestor.getCaHasRequestor().getProfiles();
        if (profiles != null) {
            if (profiles.contains("all") || profiles.contains(certprofile)) {
                return;
            }
        }

        String msg = "certprofile " + certprofile + " is not allowed";
        LOG.warn(msg);
        throw new InsuffientPermissionException(msg);
    }

    private void checkPermission(
            final CmpRequestorInfo requestor,
            final Permission requiredPermission)
    throws InsuffientPermissionException {
        X509CA ca = getCA();
        Set<Permission> permissions = ca.getCAInfo().getPermissions();
        boolean granted = false;
        if (permissions.contains(Permission.ALL) || permissions.contains(requiredPermission)) {
            Set<Permission> rPermissions = requestor.getCaHasRequestor().getPermissions();
            if (rPermissions.contains(Permission.ALL)
                    || rPermissions.contains(requiredPermission)) {
                granted = true;
            }
        }

        if (granted) {
            return;
        }

        String msg = requiredPermission.getPermission() + " is not allowed";
        LOG.warn(msg);
        throw new InsuffientPermissionException(msg);
    }

    private String getSystemInfo(
            final CmpRequestorInfo requestor,
            final Set<Integer> acceptVersions)
    throws OperationException {
        X509CA ca = getCA();
        StringBuilder sb = new StringBuilder();
        // current maximal support version is 2
        int version = 2;
        if (CollectionUtil.isNotEmpty(acceptVersions) && !acceptVersions.contains(version)) {
            Integer v = null;
            for (Integer m : acceptVersions) {
                if (m < version) {
                    v = m;
                }
            }

            if (v == null) {
                throw new OperationException(ErrorCode.BAD_REQUEST,
                    "none of versions " + acceptVersions + " is supported");
            } else {
                version = v;
            }
        }

        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
        sb.append("<systemInfo version=\"").append(version).append("\">");
        if (version == 2) {
            // CACert
            sb.append("<CACert>");
            sb.append(Base64.toBase64String(ca.getCAInfo().getCertificate().getEncodedCert()));
            sb.append("</CACert>");

            // Profiles
            Set<String> requestorProfiles = requestor.getCaHasRequestor().getProfiles();

            Set<String> supportedLocalProfileNames = new HashSet<>();
            Map<String, String> caProfileNames = ca.getCAManager().getCertprofilesForCA(
                    ca.getCAInfo().getName());
            for (String caProfileName : caProfileNames.keySet()) {
                if (requestorProfiles.contains("all")
                        || requestorProfiles.contains(caProfileName)) {
                    supportedLocalProfileNames.add(caProfileName);
                }
            }

            if (CollectionUtil.isNotEmpty(supportedLocalProfileNames)) {
                sb.append("<certprofiles>");
                for (String localname : supportedLocalProfileNames) {
                    String name = caProfileNames.get(localname);
                    CertprofileEntry entry = ca.getCAManager().getCertprofile(name);
                    if (entry.isFaulty()) {
                        continue;
                    }

                    sb.append("<certprofile>");
                    sb.append("<name>").append(localname).append("</name>");
                    sb.append("<type>").append(entry.getType()).append("</type>");
                    sb.append("<conf>");
                    String conf = entry.getConf();
                    if (StringUtil.isNotBlank(conf)) {
                        sb.append("<![CDATA[");
                        sb.append(conf);
                        sb.append("]]>");
                    }
                    sb.append("</conf>");
                    sb.append("</certprofile>");
                }

                sb.append("</certprofiles>");
            }

            sb.append("</systemInfo>");
        } else {
            throw new OperationException(ErrorCode.BAD_REQUEST, "unsupported version " + version);
        }

        return sb.toString();
    }

    @Override
    protected ConcurrentContentSigner getSigner()
    throws InvalidConfException {
        String name = getResponderName();
        return caManager.getCmpResponderWrapper(name).getSigner();
    }

    @Override
    protected GeneralName getSender()
    throws InvalidConfException {
        return caManager.getCmpResponderWrapper(getResponderName()).getSubjectAsGeneralName();
    }

    @Override
    protected boolean intendsMe(
            final GeneralName requestRecipient)
    throws InvalidConfException {
        if (requestRecipient == null) {
            return false;
        }

        if (getSender().equals(requestRecipient)) {
            return true;
        }

        if (requestRecipient.getTagNo() == GeneralName.directoryName) {
            X500Name x500Name = X500Name.getInstance(requestRecipient.getName());
            if (x500Name.equals(
                    caManager.getCmpResponderWrapper(getResponderName()).getSubjectAsX500Name())) {
                return true;
            }
        }

        return false;
    }

    @Override
    protected CmpRequestorInfo getRequestor(
            final X500Name requestorSender) {
        return getCA().getRequestor(requestorSender);
    }

    private PKIBody cmpEnrollCert(
            final PKIHeaderBuilder respHeader,
            final CmpControl cmpControl,
            final PKIHeader reqHeader,
            final PKIBody reqBody,
            final CmpRequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final AuditEvent auditEvent)
    throws InsuffientPermissionException {
        long confirmWaitTime = cmpControl.getConfirmWaitTime();
        if (confirmWaitTime < 0) {
            confirmWaitTime *= -1;
        }
        confirmWaitTime *= 1000; // second to millisecond
        boolean sendCaCert = cmpControl.isSendCaCert();

        PKIBody respBody;

        int type = reqBody.getType();
        switch (type) {
        case PKIBody.TYPE_CERT_REQ:
            addAutitEventType(auditEvent, "CERT_REQ");
            checkPermission(requestor, Permission.ENROLL_CERT);
            respBody = processCr(requestor, user, tid, reqHeader,
                    (CertReqMessages) reqBody.getContent(), confirmWaitTime,
                    sendCaCert, auditEvent);
            break;
        case PKIBody.TYPE_KEY_UPDATE_REQ:
            addAutitEventType(auditEvent, "KEY_UPDATE");
            checkPermission(requestor, Permission.KEY_UPDATE);
            respBody = processKur(requestor, user, tid, reqHeader,
                    (CertReqMessages) reqBody.getContent(), confirmWaitTime,
                    sendCaCert, auditEvent);
            break;
        case PKIBody.TYPE_P10_CERT_REQ:
            addAutitEventType(auditEvent, "CERT_REQ");
            checkPermission(requestor, Permission.ENROLL_CERT);
            respBody = processP10cr(requestor, user, tid, reqHeader,
                    (CertificationRequest) reqBody.getContent(), confirmWaitTime,
                    sendCaCert, auditEvent);
            break;
        case PKIBody.TYPE_CROSS_CERT_REQ:
            addAutitEventType(auditEvent, "CROSS_CERT_REQ");
            checkPermission(requestor, Permission.CROSS_CERT_ENROLL);
            respBody = processCcp(requestor, user, tid, reqHeader,
                    (CertReqMessages) reqBody.getContent(), confirmWaitTime,
                    sendCaCert, auditEvent);
            break;
        default:
            throw new RuntimeException("should not reach here");
        } // switch type

        InfoTypeAndValue tv = null;
        if (!cmpControl.isConfirmCert() && CmpUtil.isImplictConfirm(reqHeader)) {
            pendingCertPool.removeCertificates(tid.getOctets());
            tv = CmpUtil.getImplictConfirmGeneralInfo();
        } else {
            Date now = new Date();
            respHeader.setMessageTime(new ASN1GeneralizedTime(now));
            tv = new InfoTypeAndValue(
                    CMPObjectIdentifiers.it_confirmWaitTime,
                    new ASN1GeneralizedTime(
                            new Date(System.currentTimeMillis() + confirmWaitTime)));
        }

        respHeader.setGeneralInfo(tv);
        return respBody;
    }

    private PKIBody cmpRevokeOrUnrevokeOrRemoveCertificates(
            final PKIHeaderBuilder respHeader,
            final CmpControl cmpControl,
            final PKIHeader reqHeader,
            final PKIBody reqBody,
            final CmpRequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final AuditEvent auditEvent)
    throws InsuffientPermissionException {
        Permission requiredPermission = null;
        boolean allRevdetailsOfSameType = true;

        RevReqContent rr = (RevReqContent) reqBody.getContent();
        RevDetails[] revContent = rr.toRevDetailsArray();

        int n = revContent.length;
        for (int i = 0; i < n; i++) {
            RevDetails revDetails = revContent[i];
            Extensions crlDetails = revDetails.getCrlEntryDetails();
            int reasonCode = CRLReason.UNSPECIFIED.getCode();
            if (crlDetails != null) {
                ASN1ObjectIdentifier extId = Extension.reasonCode;
                ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
                if (extValue != null) {
                    reasonCode = ((ASN1Enumerated) extValue).getValue().intValue();
                }
            }

            if (reasonCode == XipkiCmpConstants.CRL_REASON_REMOVE) {
                if (requiredPermission == null) {
                    addAutitEventType(auditEvent, "CERT_REMOVE");
                    requiredPermission = Permission.REMOVE_CERT;
                } else if (requiredPermission != Permission.REMOVE_CERT) {
                    allRevdetailsOfSameType = false;
                    break;
                }
            } else if (reasonCode == CRLReason.REMOVE_FROM_CRL.getCode()) {
                if (requiredPermission == null) {
                    addAutitEventType(auditEvent, "CERT_UNREVOKE");
                    requiredPermission = Permission.UNREVOKE_CERT;
                } else if (requiredPermission != Permission.UNREVOKE_CERT) {
                    allRevdetailsOfSameType = false;
                    break;
                }
            } else {
                if (requiredPermission == null) {
                    addAutitEventType(auditEvent, "CERT_REVOKE");
                    requiredPermission = Permission.REVOKE_CERT;
                } else if (requiredPermission != Permission.REVOKE_CERT) {
                    allRevdetailsOfSameType = false;
                    break;
                }
            }
        }

        if (!allRevdetailsOfSameType) {
            ErrorMsgContent emc = new ErrorMsgContent(
                    new PKIStatusInfo(PKIStatus.rejection,
                    new PKIFreeText("not all revDetails are of the same type"),
                    new PKIFailureInfo(PKIFailureInfo.badRequest)));

            return new PKIBody(PKIBody.TYPE_ERROR, emc);
        } else {
            checkPermission(requestor, requiredPermission);
            return revokeOrUnrevokeOrRemoveCertificates(rr, auditEvent, requiredPermission);
        }
    }

    private PKIBody cmpGeneralMsg(
            final PKIHeaderBuilder respHeader,
            final CmpControl cmpControl,
            final PKIHeader reqHeader,
            final PKIBody reqBody,
            final CmpRequestorInfo requestor,
            final String user,
            final ASN1OctetString tid,
            final AuditEvent auditEvent)
    throws InsuffientPermissionException {
        GenMsgContent genMsgBody = (GenMsgContent) reqBody.getContent();
        InfoTypeAndValue[] itvs = genMsgBody.toInfoTypeAndValueArray();

        InfoTypeAndValue itv = null;
        if (itvs != null && itvs.length > 0) {
            for (InfoTypeAndValue _itv : itvs) {
                String itvType = _itv.getInfoType().getId();
                if (knownGenMsgIds.contains(itvType)) {
                    itv = _itv;
                    break;
                }
            }
        }

        if (itv == null) {
            String statusMessage = "PKIBody type " + PKIBody.TYPE_GEN_MSG
                    + " is only supported with the sub-types "
                    + knownGenMsgIds.toString();
            return createErrorMsgPKIBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                    statusMessage);
        }

        InfoTypeAndValue itvResp = null;
        ASN1ObjectIdentifier infoType = itv.getInfoType();

        int failureInfo;
        try {
            X509CA ca = getCA();
            if (CMPObjectIdentifiers.it_currentCRL.equals(infoType)) {
                addAutitEventType(auditEvent, "CRL_DOWNLOAD");
                checkPermission(requestor, Permission.GET_CRL);
                CertificateList crl = ca.getCurrentCRL();

                if (itv.getInfoValue() == null) { // as defined in RFC 4210
                    crl = ca.getCurrentCRL();
                } else {
                    // xipki extension
                    ASN1Integer crlNumber = ASN1Integer.getInstance(itv.getInfoValue());
                    crl = ca.getCRL(crlNumber.getPositiveValue());
                }

                if (crl == null) {
                    String statusMessage = "no CRL is available";
                    return createErrorMsgPKIBody(PKIStatus.rejection, PKIFailureInfo.systemFailure,
                            statusMessage);
                }

                itvResp = new InfoTypeAndValue(infoType, crl);
            } else if (ObjectIdentifiers.id_xipki_cm_cmpGenmsg.equals(infoType)) {
                ASN1Encodable asn1 = itv.getInfoValue();
                ASN1Integer asn1Code = null;
                ASN1Encodable reqValue = null;

                try {
                    ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
                    asn1Code = ASN1Integer.getInstance(seq.getObjectAt(0));
                    if (seq.size() > 1) {
                        reqValue = seq.getObjectAt(1);
                    }
                } catch (IllegalArgumentException e) {
                    String statusMessage = "invalid value of the InfoTypeAndValue for "
                            + ObjectIdentifiers.id_xipki_cm_cmpGenmsg.getId();
                    return createErrorMsgPKIBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                            statusMessage);
                }

                ASN1Encodable respValue;

                int action = asn1Code.getPositiveValue().intValue();
                switch (action) {
                case XipkiCmpConstants.ACTION_GEN_CRL:
                    addAutitEventType(auditEvent, "CRL_GEN_ONDEMAND");
                    checkPermission(requestor, Permission.GEN_CRL);
                    X509CRL _crl = ca.generateCRLonDemand(auditEvent);
                    if (_crl == null) {
                        String statusMessage = "CRL generation is not activated";
                        return createErrorMsgPKIBody(PKIStatus.rejection,
                                PKIFailureInfo.systemFailure, statusMessage);
                    } else {
                        respValue = CertificateList.getInstance(_crl.getEncoded());
                    }
                    break;
                case XipkiCmpConstants.ACTION_GET_CRL_WITH_SN:
                    addAutitEventType(auditEvent, "CRL_DOWNLOAD_WITH_SN");
                    checkPermission(requestor, Permission.GET_CRL);

                    ASN1Integer crlNumber = ASN1Integer.getInstance(reqValue);
                    respValue = ca.getCRL(crlNumber.getPositiveValue());
                    if (respValue == null) {
                        String statusMessage = "no CRL is available";
                        return createErrorMsgPKIBody(PKIStatus.rejection,
                                PKIFailureInfo.systemFailure, statusMessage);
                    }
                    break;
                case XipkiCmpConstants.ACTION_GET_CAINFO:
                    addAutitEventType(auditEvent, "GET_SYSTEMINFO");
                    Set<Integer> acceptVersions = new HashSet<>();
                    if (reqValue != null) {
                        ASN1Sequence seq = DERSequence.getInstance(reqValue);
                        int size = seq.size();
                        for (int i = 0; i < size; i++) {
                            ASN1Integer a = ASN1Integer.getInstance(seq.getObjectAt(i));
                            acceptVersions.add(a.getPositiveValue().intValue());
                        }
                    }

                    if (CollectionUtil.isEmpty(acceptVersions)) {
                        acceptVersions.add(1);
                    }

                    String systemInfo = getSystemInfo(requestor, acceptVersions);
                    respValue = new DERUTF8String(systemInfo);
                    break;
                default:
                    String statusMessage = "unsupported XiPKI action code '" + action + "'";
                    return createErrorMsgPKIBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                            statusMessage);
                } // end switch (action)

                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add(asn1Code);
                if (respValue != null) {
                    v.add(respValue);
                }
                itvResp = new InfoTypeAndValue(infoType, new DERSequence(v));
            }

            GenRepContent genRepContent = new GenRepContent(itvResp);
            return new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
        } catch (OperationException e) {
            failureInfo = PKIFailureInfo.systemFailure;
            String statusMessage = null;
            ErrorCode code = e.getErrorCode();
            switch (code) {
            case BAD_REQUEST:
                failureInfo = PKIFailureInfo.badRequest;
                statusMessage = e.getErrorMessage();
                break;
            case DATABASE_FAILURE:
            case SYSTEM_FAILURE:
                statusMessage = code.name();
                break;
            default:
                statusMessage = code.name() + ": " + e.getErrorMessage();
                break;
            } // end switch (code)

            return createErrorMsgPKIBody(PKIStatus.rejection, failureInfo, statusMessage);
        } catch (CRLException e) {
            String statusMessage = "CRLException: " + e.getMessage();
            return createErrorMsgPKIBody(PKIStatus.rejection, PKIFailureInfo.systemFailure,
                    statusMessage);
        }
    }

    private static PKIBody createErrorMsgPKIBody(
            final PKIStatus pkiStatus,
            final int failureInfo,
            final String statusMessage) {
        PKIFreeText pkiStatusMsg = (statusMessage == null)
                ? null
                : new PKIFreeText(statusMessage);

        ErrorMsgContent emc = new ErrorMsgContent(
                new PKIStatusInfo(pkiStatus,
                        pkiStatusMsg,
                        new PKIFailureInfo(failureInfo)));

        return new PKIBody(PKIBody.TYPE_ERROR, emc);
    }

    private static void addAutitEventType(
            final AuditEvent auditEvent,
            final String eventType) {
        if (auditEvent != null) {
            auditEvent.addEventData(new AuditEventData("eventType", eventType));
        }
    }

}
