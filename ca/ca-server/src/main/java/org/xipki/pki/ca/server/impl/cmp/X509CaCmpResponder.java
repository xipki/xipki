/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
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
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.api.AuditChildEvent;
import org.xipki.commons.audit.api.AuditEvent;
import org.xipki.commons.audit.api.AuditStatus;
import org.xipki.commons.common.HealthCheckResult;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.DateUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.AlgorithmValidator;
import org.xipki.commons.security.ConcurrentContentSigner;
import org.xipki.commons.security.CrlReason;
import org.xipki.commons.security.ObjectIdentifiers;
import org.xipki.commons.security.X509Cert;
import org.xipki.commons.security.XiSecurityConstants;
import org.xipki.commons.security.util.AlgorithmUtil;
import org.xipki.commons.security.util.X509Util;
import org.xipki.pki.ca.api.InsuffientPermissionException;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.RequestorInfo;
import org.xipki.pki.ca.api.X509CertWithDbId;
import org.xipki.pki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.pki.ca.common.cmp.CmpUtf8Pairs;
import org.xipki.pki.ca.common.cmp.CmpUtil;
import org.xipki.pki.ca.server.impl.CaManagerImpl;
import org.xipki.pki.ca.server.impl.CertTemplateData;
import org.xipki.pki.ca.server.impl.X509Ca;
import org.xipki.pki.ca.server.impl.store.X509CertWithRevocationInfo;
import org.xipki.pki.ca.server.impl.util.CaUtil;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControl;
import org.xipki.pki.ca.server.mgmt.api.Permission;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CaCmpResponder extends CmpResponder {

    private class PendingPoolCleaner implements Runnable {

        @Override
        public void run() {
            Set<X509CertificateInfo> remainingCerts =
                    pendingCertPool.removeConfirmTimeoutedCertificates();

            if (CollectionUtil.isEmpty(remainingCerts)) {
                return;
            }

            Date invalidityDate = new Date();
            X509Ca ca = getCa();
            for (X509CertificateInfo remainingCert : remainingCerts) {
                BigInteger serialNumber = null;
                try {
                    serialNumber = remainingCert.getCert().getCert().getSerialNumber();
                    ca.revokeCertificate(serialNumber, CrlReason.CESSATION_OF_OPERATION,
                            invalidityDate);
                } catch (Throwable th) {
                    LOG.error("could not revoke certificate (CA={}, serialNumber={}): {}",
                            ca.getCaInfo().getName(), LogUtil.formatCsn(serialNumber),
                            th.getMessage());
                }
            }
        } // method run

    } // class PendingPoolCleaner

    private static final Set<String> KNOWN_GENMSG_IDS = new HashSet<>();

    private static final Logger LOG = LoggerFactory.getLogger(X509CaCmpResponder.class);

    private final PendingCertificatePool pendingCertPool;

    private final String caName;

    private final CaManagerImpl caManager;

    static {
        KNOWN_GENMSG_IDS.add(CMPObjectIdentifiers.it_currentCRL.getId());
        KNOWN_GENMSG_IDS.add(ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId());
    }

    public X509CaCmpResponder(final CaManagerImpl caManager, final String caName) {
        super(caManager.getSecurityFactory());

        this.caManager = caManager;
        this.pendingCertPool = new PendingCertificatePool();
        this.caName = caName;

        PendingPoolCleaner pendingPoolCleaner = new PendingPoolCleaner();
        caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(pendingPoolCleaner, 10, 10,
                TimeUnit.MINUTES);
    }

    public X509Ca getCa() {
        try {
            return caManager.getX509Ca(caName);
        } catch (CaMgmtException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean isInService() {
        if (!super.isInService()) {
            return false;
        }

        if (CaStatus.ACTIVE != getCa().getCaInfo().getStatus()) {
            return false;
        }

        return true;
    }

    public HealthCheckResult healthCheck() {
        HealthCheckResult result = getCa().healthCheck();

        boolean healthy = result.isHealthy();

        boolean responderHealthy = caManager.getCmpResponderWrapper(
                getResponderName()).getSigner().isHealthy();
        healthy &= responderHealthy;

        HealthCheckResult responderHealth = new HealthCheckResult("Responder");
        responderHealth.setHealthy(responderHealthy);
        result.addChildCheck(responderHealth);

        result.setHealthy(healthy);
        return result;
    }

    public String getResponderName() {
        return getCa().getCaInfo().getResponderName();
    }

    @Override
    protected PKIMessage doProcessPkiMessage(PKIMessage request, final RequestorInfo requestor,
            final String user, final ASN1OctetString tid, final GeneralPKIMessage message,
            final AuditEvent auditEvent) {
        if (!(requestor instanceof CmpRequestorInfo)) {
            throw new IllegalArgumentException(
                    "unknown requestor type " + requestor.getClass().getName());
        }

        CmpRequestorInfo tmpRequestor = (CmpRequestorInfo) requestor;
        if (tmpRequestor != null) {
            auditEvent.addEventData("requestor", tmpRequestor.getCert().getSubject());
        }

        PKIHeader reqHeader = message.getHeader();
        PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
                reqHeader.getPvno().getValue().intValue(), getSender(), reqHeader.getSender());
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
            case PKIBody.TYPE_CROSS_CERT_REQ:
                respBody = cmpEnrollCert(request, respHeader, cmpControl, reqHeader, reqBody,
                        tmpRequestor, user, tid, auditEvent);
                break;
            case PKIBody.TYPE_CERT_CONFIRM:
                addAutitEventType(auditEvent, "CERT_CONFIRM");
                CertConfirmContent certConf = (CertConfirmContent) reqBody.getContent();
                respBody = confirmCertificates(tid, certConf);
                break;
            case PKIBody.TYPE_REVOCATION_REQ:
                respBody = cmpRevokeOrUnrevokeOrRemoveCertificates(request, respHeader, cmpControl,
                        reqHeader, reqBody, tmpRequestor, user, tid, auditEvent);
                break;
            case PKIBody.TYPE_CONFIRM:
                addAutitEventType(auditEvent, "CONFIRM");
                respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
                break;
            case PKIBody.TYPE_ERROR:
                addAutitEventType(auditEvent, "ERROR");
                revokePendingCertificates(tid);
                respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
                break;
            case PKIBody.TYPE_GEN_MSG:
                respBody = cmpGeneralMsg(respHeader, cmpControl, reqHeader, reqBody,
                        tmpRequestor, user, tid, auditEvent);
                break;
            default:
                addAutitEventType(auditEvent, "PKIBody." + type);
                respBody = buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                        "unsupported type " + type);
                break;
            } // end switch (type)
        } catch (InsuffientPermissionException ex) {
            ErrorMsgContent emc = new ErrorMsgContent(
                    new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(ex.getMessage()),
                            new PKIFailureInfo(PKIFailureInfo.notAuthorized)));

            respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
        }

        if (respBody.getType() == PKIBody.TYPE_ERROR) {
            ErrorMsgContent errorMsgContent = (ErrorMsgContent) respBody.getContent();

            AuditStatus auditStatus = AuditStatus.FAILED;
            org.xipki.pki.ca.common.cmp.PkiStatusInfo pkiStatus =
                    new org.xipki.pki.ca.common.cmp.PkiStatusInfo(
                            errorMsgContent.getPKIStatusInfo());

            if (pkiStatus.getPkiFailureInfo() == PKIFailureInfo.systemFailure) {
                auditStatus = AuditStatus.FAILED;
            }
            auditEvent.setStatus(auditStatus);

            String statusString = pkiStatus.getStatusMessage();
            if (statusString != null) {
                auditEvent.addEventData("message", statusString);
            }
        } else if (auditEvent.getStatus() == null) {
            auditEvent.setStatus(AuditStatus.SUCCESSFUL);
        }

        return new PKIMessage(respHeader.build(), respBody);
    } // method doProcessPKIMessage

    /**
     * handle the PKI body with the choice {@code cr}.
     *
     */
    private PKIBody processCr(final PKIMessage request, final CmpRequestorInfo requestor,
            final String user, final ASN1OctetString tid, final PKIHeader reqHeader,
            final CertReqMessages cr, final CmpControl cmpControl, final AuditEvent auditEvent) {
        CertRepMessage repMessage = processCertReqMessages(request, requestor, user, tid, reqHeader,
                cr, false, cmpControl, auditEvent);
        return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
    }

    private PKIBody processKur(final PKIMessage request, final CmpRequestorInfo requestor,
            final String user, final ASN1OctetString tid, final PKIHeader reqHeader,
            final CertReqMessages kur, final CmpControl cmpControl, final AuditEvent auditEvent) {
        CertRepMessage repMessage = processCertReqMessages(request, requestor, user, tid, reqHeader,
                kur, true, cmpControl, auditEvent);
        return new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, repMessage);
    }

    /**
     * handle the PKI body with the choice {@code cr}.
     *
     */
    private PKIBody processCcp(final PKIMessage request, final CmpRequestorInfo requestor,
            final String user, final ASN1OctetString tid, final PKIHeader reqHeader,
            final CertReqMessages cr, final CmpControl cmpControl, final AuditEvent auditEvent) {
        CertRepMessage repMessage = processCertReqMessages(request, requestor, user, tid, reqHeader,
                cr, false, cmpControl, auditEvent);
        return new PKIBody(PKIBody.TYPE_CROSS_CERT_REP, repMessage);
    }

    private CertRepMessage processCertReqMessages(final PKIMessage request,
            final CmpRequestorInfo requestor, final String user, final ASN1OctetString tid,
            final PKIHeader reqHeader, final CertReqMessages kur, final boolean keyUpdate,
            final CmpControl cmpControl, final AuditEvent auditEvent) {
        CmpRequestorInfo tmpRequestor = (CmpRequestorInfo) requestor;

        CertReqMsg[] certReqMsgs = kur.toCertReqMsgArray();
        final int n = certReqMsgs.length;

        Map<Integer, CertTemplateData> certTemplateDatas = new HashMap<>(n * 10 / 6);
        Map<Integer, AuditChildEvent> auditChildEvents = new HashMap<>(n * 10 / 6);
        Map<Integer, CertResponse> certResponses = new HashMap<>(n * 10 / 6);
        Map<Integer, ASN1Integer> certReqIds = new HashMap<>(n * 10 / 6);

        // pre-process requests
        for (int i = 0; i < n; i++) {
            if (cmpControl.isGroupEnroll() && certTemplateDatas.size() != i) {
                // last certReqMsg cannot be used to enroll certificate
                break;
            }

            AuditChildEvent auditChildEvent = new AuditChildEvent();
            auditEvent.addAuditChildEvent(auditChildEvent);
            auditChildEvents.put(i, auditChildEvent);

            CertReqMsg reqMsg = certReqMsgs[i];
            CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);
            ASN1Integer certReqId = reqMsg.getCertReq().getCertReqId();
            certReqIds.put(i, certReqId);

            auditChildEvent.addEventData("certReqId", certReqId.getPositiveValue().toString());

            if (!req.hasProofOfPossession()) {
                certResponses.put(i, buildErrorCertResponse(certReqId,
                        PKIFailureInfo.badPOP, "no POP", null, auditChildEvent));
                continue;
            }

            if (!verifyPopo(req, tmpRequestor.isRa())) {
                LOG.warn("could not validate POP for requst {}", certReqId.getValue());
                certResponses.put(i, buildErrorCertResponse(certReqId,
                        PKIFailureInfo.badPOP, "invalid POP", null, auditChildEvent));
                continue;
            }

            CmpUtf8Pairs keyvalues = CmpUtil.extract(reqMsg.getRegInfo());
            String certprofileName = (keyvalues == null) ? null
                    : keyvalues.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);
            if (certprofileName == null) {
                String msg = "no certificate profile";
                certResponses.put(i, buildErrorCertResponse(certReqId,
                        PKIFailureInfo.badCertTemplate, msg, auditChildEvent));
                continue;
            }

            auditChildEvent.addEventData("certprofile", certprofileName);
            if (!isCertProfilePermitted(tmpRequestor, certprofileName)) {
                String msg = "certprofile " + certprofileName + " is not allowed";
                certResponses.put(i, buildErrorCertResponse(certReqId,
                        PKIFailureInfo.notAuthorized, msg, auditChildEvent));
                continue;
            }

            CertTemplate certTemp = req.getCertTemplate();
            OptionalValidity validity = certTemp.getValidity();

            Date notBefore = null;
            Date notAfter = null;
            if (validity != null) {
                Time time = validity.getNotBefore();
                if (time != null) {
                    notBefore = time.getDate();
                }
                time = validity.getNotAfter();
                if (time != null) {
                    notAfter = time.getDate();
                }
            }

            CertTemplateData certTempData = new CertTemplateData(certTemp.getSubject(),
                    certTemp.getPublicKey(), notBefore, notAfter,  certTemp.getExtensions(),
                    certprofileName);
            certTemplateDatas.put(i, certTempData);
        } // end for

        if (certResponses.size() == n) {
            // all error
            CertResponse[] certResps = new CertResponse[n];
            for (int i = 0; i < n; i++) {
                certResps[i] = certResponses.get(i);
            }
            return new CertRepMessage(null, certResps);
        }

        if (cmpControl.isGroupEnroll() && certTemplateDatas.size() != n) {
            // at least one certRequest cannot be used to enroll certificate
            int lastFailureIndex = certTemplateDatas.size();
            BigInteger failCertReqId = certReqIds.get(lastFailureIndex).getPositiveValue();
            CertResponse failCertResp = certResponses.get(lastFailureIndex);
            PKIStatus failStatus = PKIStatus.getInstance(
                    new ASN1Integer(failCertResp.getStatus().getStatus()));
            PKIFailureInfo failureInfo = new PKIFailureInfo(failCertResp.getStatus().getFailInfo());

            CertResponse[] certResps = new CertResponse[n];

            for (int i = 0; i < n; i++) {
                if (i == lastFailureIndex) {
                    certResps[i] = failCertResp;
                    continue;
                }

                ASN1Integer certReqId = certReqIds.get(i);
                String msg = "error in certReq " + failCertReqId;
                AuditChildEvent auditChildEvent = auditChildEvents.get(i);
                auditChildEvent.setStatus(AuditStatus.FAILED);
                auditChildEvent.addEventData("message", msg);

                PKIStatusInfo tmpStatus = generateCmpRejectionStatus(failStatus,
                        failureInfo.intValue(), msg);
                certResps[i] = new CertResponse(certReqId, tmpStatus);
            }

            return new CertRepMessage(null, certResps);
        }

        final int k = certTemplateDatas.size();
        List<CertTemplateData> certTemplateList = new ArrayList<>(k);
        List<ASN1Integer> certReqIdList = new ArrayList<>(k);
        List<AuditChildEvent> auditChildEventList = new ArrayList<>(k);
        Map<Integer, Integer> reqIndexToCertIndexMap = new HashMap<>(k * 10 / 6);

        for (int i = 0; i < n; i++) {
            if (!certTemplateDatas.containsKey(i)) {
                continue;
            }

            certTemplateList.add(certTemplateDatas.get(i));
            certReqIdList.add(certReqIds.get(i));
            auditChildEventList.add(auditChildEvents.get(i));
            reqIndexToCertIndexMap.put(i, certTemplateList.size() - 1);
        }

        List<CertResponse> generateCertResponses = generateCertificates(
                certTemplateList, certReqIdList, auditChildEventList, tmpRequestor, user, tid,
                keyUpdate, request, cmpControl);
        boolean anyCertEnrolled = false;

        CertResponse[] certResps = new CertResponse[n];
        for (int i = 0; i < n; i++) {
            if (certResponses.containsKey(i)) {
                certResps[i] = certResponses.get(i);
            } else {
                int respIndex = reqIndexToCertIndexMap.get(i);
                certResps[i] = generateCertResponses.get(respIndex);
                if (!anyCertEnrolled && certResps[i].getCertifiedKeyPair() != null) {
                    anyCertEnrolled = true;
                }
            }
        }

        CMPCertificate[] caPubs = null;
        if (anyCertEnrolled && cmpControl.isSendCaCert()) {
            caPubs = new CMPCertificate[]{getCa().getCaInfo().getCertInCmpFormat()};
        }

        return new CertRepMessage(caPubs, certResps);
    } // method processCertReqMessages

    /**
     * handle the PKI body with the choice {@code p10cr}<br/>
     * Since it is not possible to add attribute to the PKCS#10 request (CSR), the certificate
     * profile must be specified in the attribute regInfo-utf8Pairs (1.3.6.1.5.5.7.5.2.1) within
     * PKIHeader.generalInfo
     *
     */
    private PKIBody processP10cr(final PKIMessage request, final CmpRequestorInfo requestor,
            final String user, final ASN1OctetString tid, final PKIHeader reqHeader,
            final CertificationRequest p10cr, final CmpControl cmpControl,
            final AuditEvent auditEvent) {
        // verify the POP first
        CertResponse certResp;
        ASN1Integer certReqId = new ASN1Integer(-1);

        AuditChildEvent auditChildEvent = new AuditChildEvent();
        auditEvent.addAuditChildEvent(auditChildEvent);

        boolean certGenerated = false;
        X509Ca ca = getCa();

        if (!securityFactory.verifyPopo(p10cr, getCmpControl().getPopoAlgoValidator())) {
            LOG.warn("could not validate POP for the pkcs#10 requst");
            certResp = buildErrorCertResponse(certReqId, PKIFailureInfo.badPOP, "invalid POP",
                    auditChildEvent);
        } else {
            CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
            Extensions extensions = CaUtil.getExtensions(certTemp);

            X500Name subject = certTemp.getSubject();
            auditChildEvent.addEventData("req-subject", X509Util.getRfc4519Name(subject));

            SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

            CmpUtf8Pairs keyvalues = CmpUtil.extract(reqHeader.getGeneralInfo());
            String certprofileName = null;
            Date notBefore = null;
            Date notAfter = null;

            if (keyvalues != null) {
                certprofileName = keyvalues.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);

                String str = keyvalues.getValue(CmpUtf8Pairs.KEY_NOT_BEFORE);
                if (str != null) {
                    notBefore = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
                }

                str = keyvalues.getValue(CmpUtf8Pairs.KEY_NOT_AFTER);
                if (str != null) {
                    notAfter = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
                }
            }

            if (certprofileName == null) {
                certResp = buildErrorCertResponse(certReqId, PKIFailureInfo.badCertTemplate,
                        "badCertTemplate", null, auditChildEvent);
            } else {
                auditChildEvent.addEventData("certprofile", certprofileName);
                if (!isCertProfilePermitted(requestor, certprofileName)) {
                    String msg = "certprofile " + certprofileName + " is not allowed";
                    certResp = buildErrorCertResponse(certReqId,
                            PKIFailureInfo.notAuthorized, msg, auditChildEvent);
                } else {
                    CertTemplateData certTemplateData = new CertTemplateData(subject, publicKeyInfo,
                            notBefore, notAfter, extensions, certprofileName);

                    certResp = generateCertificates(Arrays.asList(certTemplateData),
                            Arrays.asList(certReqId), Arrays.asList(auditChildEvent),
                            requestor, user, tid, false, request, cmpControl).get(0);
                    certGenerated = true;
                }
            }
        }

        CMPCertificate[] caPubs = null;
        if (certGenerated && cmpControl.isSendCaCert()) {
            caPubs = new CMPCertificate[]{ca.getCaInfo().getCertInCmpFormat()};
        }
        CertRepMessage repMessage = new CertRepMessage(caPubs, new CertResponse[]{certResp});

        return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
    } // method processP10cr

    private List<CertResponse> generateCertificates(
            final List<CertTemplateData> certTemplates, final List<ASN1Integer> certReqIds,
            final List<AuditChildEvent> auditChildEvents, final CmpRequestorInfo requestor,
            final String user, final ASN1OctetString tid, final boolean keyUpdate,
            final PKIMessage request, CmpControl cmpControl) {
        X509Ca ca = getCa();

        final int n = certTemplates.size();
        List<CertResponse> ret = new ArrayList<>(n);

        if (cmpControl.isGroupEnroll()) {
            try {
                List<X509CertificateInfo> certInfos;
                if (keyUpdate) {
                    certInfos = ca.regenerateCertificates(certTemplates, requestor.isRa(),
                            requestor, user, RequestType.CMP, tid.getOctets());
                } else {
                    certInfos = ca.generateCertificates(certTemplates, requestor.isRa(), requestor,
                            user, RequestType.CMP, tid.getOctets());
                }

                // save the request
                Long reqDbId = null;
                if (ca.getCaInfo().isSaveRequest()) {
                    try {
                        byte[] encodedRequest = request.getEncoded();
                        reqDbId = ca.addRequest(encodedRequest);
                    } catch (Exception ex) {
                        LOG.warn("could not save request");
                    }
                }

                for (int i = 0; i < n; i++) {
                    X509CertificateInfo certInfo = certInfos.get(i);
                    ret.add(postProcessCertInfo(certReqIds.get(i), auditChildEvents.get(i),
                            certInfo, tid, cmpControl));
                    if (reqDbId != null) {
                        ca.addRequestCert(reqDbId, certInfo.getCert().getCertId());
                    }
                }
            } catch (OperationException ex) {
                for (int i = 0; i < n; i++) {
                    ret.add(postProcessException(certReqIds.get(i), ex, auditChildEvents.get(i)));
                }
            }
        } else {
            Long reqDbId = null;
            boolean savingRequestFailed = false;

            for (int i = 0; i < n; i++) {
                CertTemplateData certTemplate = certTemplates.get(i);
                ASN1Integer certReqId = certReqIds.get(i);
                AuditChildEvent auditChildEvent = auditChildEvents.get(i);

                X509CertificateInfo certInfo;
                try {
                    if (keyUpdate) {
                        certInfo = ca.regenerateCertificate(certTemplate, requestor.isRa(),
                                requestor, user, RequestType.CMP, tid.getOctets());
                    } else {
                        certInfo = ca.generateCertificate(certTemplate, requestor.isRa(), requestor,
                                user, RequestType.CMP, tid.getOctets());
                    }

                    if (ca.getCaInfo().isSaveRequest()) {
                        if (reqDbId == null && !savingRequestFailed) {
                            try {
                                byte[] encodedRequest = request.getEncoded();
                                reqDbId = ca.addRequest(encodedRequest);
                            } catch (Exception ex) {
                                savingRequestFailed = true;
                                LOG.warn("could not save request");
                            }
                        }

                        if (reqDbId != null) {
                            ca.addRequestCert(reqDbId, certInfo.getCert().getCertId());
                        }
                    }

                    ret.add(postProcessCertInfo(certReqId, auditChildEvent, certInfo, tid,
                            cmpControl));
                } catch (OperationException ex) {
                    ret.add(postProcessException(certReqId, ex, auditChildEvent));
                }
            }
        }

        return ret;
    } // method generateCertificates

    private CertResponse postProcessCertInfo(ASN1Integer certReqId, AuditChildEvent auditChildEvent,
            X509CertificateInfo certInfo, ASN1OctetString tid, CmpControl cmpControl) {
        auditChildEvent.addEventData("req-subject", certInfo.getCert().getSubject());

        if (cmpControl.isConfirmCert()) {
            pendingCertPool.addCertificate(tid.getOctets(), certReqId.getPositiveValue(), certInfo,
                System.currentTimeMillis() + cmpControl.getConfirmWaitTimeMs());
        }

        String warningMsg = certInfo.getWarningMessage();

        PKIStatusInfo statusInfo;
        if (StringUtil.isBlank(warningMsg)) {
            statusInfo = certInfo.isAlreadyIssued()
                    ? new PKIStatusInfo(PKIStatus.grantedWithMods,
                        new PKIFreeText("ALREADY_ISSUED"))
                    : new PKIStatusInfo(PKIStatus.granted);
        } else {
            statusInfo = new PKIStatusInfo(PKIStatus.grantedWithMods,
                    new PKIFreeText(warningMsg));
        }

        auditChildEvent.setStatus(AuditStatus.SUCCESSFUL);

        CertOrEncCert cec = new CertOrEncCert(
                CMPCertificate.getInstance(certInfo.getCert().getEncodedCert()));
        CertifiedKeyPair kp = new CertifiedKeyPair(cec);
        return new CertResponse(certReqId, statusInfo, kp, null);
    }

    private PKIBody revokeOrUnrevokeOrRemoveCertificates(final PKIMessage request,
            final RevReqContent rr, final AuditEvent auditEvent, final Permission permission) {
        RevDetails[] revContent = rr.toRevDetailsArray();

        RevRepContentBuilder repContentBuilder = new RevRepContentBuilder();
        final int n = revContent.length;
        // test the request
        for (int i = 0; i < n; i++) {
            RevDetails revDetails = revContent[i];

            CertTemplate certDetails = revDetails.getCertDetails();
            X500Name issuer = certDetails.getIssuer();
            ASN1Integer serialNumber = certDetails.getSerialNumber();

            try {
                X500Name caSubject = getCa().getCaInfo().getCertificate().getSubjectAsX500Name();

                if (issuer == null) {
                    return buildErrorMsgPkiBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate, "issuer is not present");
                } else if (!issuer.equals(caSubject)) {
                    return buildErrorMsgPkiBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate, "issuer not targets at the CA");
                } else if (serialNumber == null) {
                    return buildErrorMsgPkiBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate, "serialNumber is not present");
                } else if (certDetails.getSigningAlg() != null
                        || certDetails.getValidity() != null
                        || certDetails.getSubject() != null
                        || certDetails.getPublicKey() != null
                        || certDetails.getIssuerUID() != null
                        || certDetails.getSubjectUID() != null
                        || certDetails.getExtensions() != null) {
                    return buildErrorMsgPkiBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate,
                            "only version, issuer and serialNumber in RevDetails.certDetails are "
                            + "allowed, but more is specified");
                }
            } catch (IllegalArgumentException ex) {
                return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                        "the request is not invalid");
            }
        } // end for

        byte[] encodedRequest = null;
        if (getCa().getCaInfo().isSaveRequest()) {
            try {
                encodedRequest = request.getEncoded();
            } catch (IOException ex) {
                LOG.warn("could not encode request");
                encodedRequest = null;
            }
        }

        Long reqDbId = null;

        for (int i = 0; i < n; i++) {
            AuditChildEvent auditChildEvent = new AuditChildEvent();
            auditEvent.addAuditChildEvent(auditChildEvent);

            RevDetails revDetails = revContent[i];

            CertTemplate certDetails = revDetails.getCertDetails();
            ASN1Integer serialNumber = certDetails.getSerialNumber();
            // serialNumber is not null due to the check in the previous for-block.

            X500Name caSubject = getCa().getCaInfo().getCertificate().getSubjectAsX500Name();
            BigInteger snBigInt = serialNumber.getPositiveValue();
            CertId certId = new CertId(new GeneralName(caSubject), serialNumber);

            auditChildEvent.addEventData("serialNumber", LogUtil.formatCsn(snBigInt));

            PKIStatusInfo status;

            try {
                Object returnedObj = null;
                Long certDbId = null;
                X509Ca ca = getCa();
                if (Permission.UNREVOKE_CERT == permission) {
                    // unrevoke
                    returnedObj = ca.unrevokeCertificate(snBigInt);
                    if (returnedObj != null) {
                        certDbId = ((X509CertWithDbId) returnedObj).getCertId();
                    }
                } else if (Permission.REMOVE_CERT == permission) {
                    // remove
                    returnedObj = ca.removeCertificate(snBigInt);
                } else {
                    // revoke
                    Date invalidityDate = null;
                    CrlReason reason = null;

                    Extensions crlDetails = revDetails.getCrlEntryDetails();
                    if (crlDetails != null) {
                        ASN1ObjectIdentifier extId = Extension.reasonCode;
                        ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
                        if (extValue != null) {
                            int reasonCode =
                                    ASN1Enumerated.getInstance(extValue).getValue().intValue();
                            reason = CrlReason.forReasonCode(reasonCode);
                        }

                        extId = Extension.invalidityDate;
                        extValue = crlDetails.getExtensionParsedValue(extId);
                        if (extValue != null) {
                            try {
                                invalidityDate =
                                        ASN1GeneralizedTime.getInstance(extValue).getDate();
                            } catch (ParseException ex) {
                                throw new OperationException(ErrorCode.INVALID_EXTENSION,
                                        "invalid extension " + extId.getId());
                            }
                        }
                    } // end if (crlDetails)

                    if (reason == null) {
                        reason = CrlReason.UNSPECIFIED;
                    }

                    auditChildEvent.addEventData("reason", reason.getDescription());
                    if (invalidityDate != null) {
                        String value = DateUtil.toUtcTimeyyyyMMddhhmmss(invalidityDate);
                        auditChildEvent.addEventData("invalidityDate", value);
                    }

                    returnedObj = ca.revokeCertificate(snBigInt, reason, invalidityDate);
                    if (returnedObj != null) {
                        certDbId = ((X509CertWithRevocationInfo) returnedObj).getCert().getCertId();
                    }
                } // end if (permission)

                if (returnedObj == null) {
                    throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
                }

                if (certDbId != null && ca.getCaInfo().isSaveRequest()) {
                    if (reqDbId == null) {
                        reqDbId = ca.addRequest(encodedRequest);
                    }
                    ca.addRequestCert(reqDbId, certDbId);
                }
                status = new PKIStatusInfo(PKIStatus.granted);
                auditChildEvent.setStatus(AuditStatus.SUCCESSFUL);
            } catch (OperationException ex) {
                ErrorCode code = ex.getErrorCode();
                LOG.warn("{} certificate, OperationException: code={}, message={}",
                        permission.name(), code.name(), ex.getErrorMessage());
                String errorMessage;
                switch (code) {
                case DATABASE_FAILURE:
                case SYSTEM_FAILURE:
                    errorMessage = code.name();
                    break;
                default:
                    errorMessage = code.name() + ": " + ex.getErrorMessage();
                    break;
                } // end switch code

                auditChildEvent.setStatus(AuditStatus.FAILED);
                auditChildEvent.addEventData("message", code.name());

                int failureInfo = getPKiFailureInfo(ex);
                status = generateCmpRejectionStatus(failureInfo, errorMessage);
            } // end try

            repContentBuilder.add(status, certId);
        } // end for

        return new PKIBody(PKIBody.TYPE_REVOCATION_REP, repContentBuilder.build());
    } // method revokeOrUnrevokeOrRemoveCertificates

    private CertResponse postProcessException(ASN1Integer certReqId, OperationException ex,
            AuditChildEvent auditChildEvent) {
        ErrorCode code = ex.getErrorCode();
        LOG.warn("generate certificate, OperationException: code={}, message={}",
                code.name(), ex.getErrorMessage());

        String errorMessage;
        switch (code) {
        case DATABASE_FAILURE:
        case SYSTEM_FAILURE:
            errorMessage = code.name();
            break;
        default:
            errorMessage = code.name() + ": " + ex.getErrorMessage();
            break;
        } // end switch code

        auditChildEvent.setStatus(AuditStatus.FAILED);
        auditChildEvent.addEventData("message", code.name());

        int failureInfo = getPKiFailureInfo(ex);
        return new CertResponse(certReqId,
                generateCmpRejectionStatus(failureInfo, errorMessage));
    }

    private int getPKiFailureInfo(OperationException ex) {
        ErrorCode code = ex.getErrorCode();

        int failureInfo;
        switch (code) {
        case ALREADY_ISSUED:
            failureInfo = PKIFailureInfo.badRequest;
            break;
        case BAD_CERT_TEMPLATE:
            failureInfo = PKIFailureInfo.badCertTemplate;
            break;
        case BAD_REQUEST:
            failureInfo = PKIFailureInfo.badRequest;
            break;
        case CERT_REVOKED:
            failureInfo = PKIFailureInfo.certRevoked;
            break;
        case CERT_UNREVOKED:
            failureInfo = PKIFailureInfo.notAuthorized;
            break;
        case BAD_POP:
            failureInfo = PKIFailureInfo.badPOP;
            break;
        case CRL_FAILURE:
            failureInfo = PKIFailureInfo.systemFailure;
            break;
        case DATABASE_FAILURE:
            failureInfo = PKIFailureInfo.systemFailure;
            break;
        case NOT_PERMITTED:
            failureInfo = PKIFailureInfo.notAuthorized;
            break;
        case INSUFFICIENT_PERMISSION:
            failureInfo = PKIFailureInfo.notAuthorized;
            break;
        case INVALID_EXTENSION:
            failureInfo = PKIFailureInfo.badRequest;
            break;
        case SYSTEM_FAILURE:
            failureInfo = PKIFailureInfo.systemFailure;
            break;
        case SYSTEM_UNAVAILABLE:
            failureInfo = PKIFailureInfo.systemUnavail;
            break;
        case UNKNOWN_CERT:
            failureInfo = PKIFailureInfo.badCertId;
            break;
        case UNKNOWN_CERT_PROFILE:
            failureInfo = PKIFailureInfo.badCertTemplate;
            break;
        default:
            failureInfo = PKIFailureInfo.systemFailure;
            break;
        } // end switch (code)

        return failureInfo;
    }

    private PKIBody confirmCertificates(final ASN1OctetString transactionId,
            final CertConfirmContent certConf) {
        CertStatus[] certStatuses = certConf.toCertStatusArray();

        boolean successful = true;
        for (CertStatus certStatus : certStatuses) {
            ASN1Integer certReqId = certStatus.getCertReqId();
            byte[] certHash = certStatus.getCertHash().getOctets();
            X509CertificateInfo certInfo = pendingCertPool.removeCertificate(
                    transactionId.getOctets(), certReqId.getPositiveValue(), certHash);
            if (certInfo == null) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("no cert under transactionId={}, certReqId={} and certHash=0X{}",
                            transactionId, certReqId.getPositiveValue(), Hex.toHexString(certHash));
                }
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
            X509Ca ca = getCa();
            try {
                ca.revokeCertificate(serialNumber, CrlReason.CESSATION_OF_OPERATION, new Date());
            } catch (OperationException ex) {
                LogUtil.warn(LOG, ex, "could not revoke certificate ca=" + ca.getCaInfo().getName()
                        + " serialNumber=" + LogUtil.formatCsn(serialNumber));
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
    } // method confirmCertificates

    private boolean revokePendingCertificates(final ASN1OctetString transactionId) {
        Set<X509CertificateInfo> remainingCerts = pendingCertPool.removeCertificates(
                transactionId.getOctets());

        if (CollectionUtil.isEmpty(remainingCerts)) {
            return true;
        }

        boolean successful = true;
        Date invalidityDate = new Date();
        X509Ca ca = getCa();
        for (X509CertificateInfo remainingCert : remainingCerts) {
            try {
                ca.revokeCertificate(remainingCert.getCert().getCert().getSerialNumber(),
                    CrlReason.CESSATION_OF_OPERATION, invalidityDate);
            } catch (OperationException ex) {
                successful = false;
            }
        }

        return successful;
    } // method revokePendingCertificates

    private boolean verifyPopo(final CertificateRequestMessage certRequest,
            final boolean allowRaPopo) {
        int popType = certRequest.getProofOfPossessionType();
        if (popType == CertificateRequestMessage.popRaVerified && allowRaPopo) {
            return true;
        }

        if (popType != CertificateRequestMessage.popSigningKey) {
            LOG.error("unsupported POP type: " + popType);
            return false;
        }

        // check the POP signature algorithm
        ProofOfPossession pop = certRequest.toASN1Structure().getPopo();
        POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());
        AlgorithmIdentifier popoAlgId = popoSign.getAlgorithmIdentifier();
        AlgorithmValidator algoValidator = getCmpControl().getPopoAlgoValidator();
        if (!algoValidator.isAlgorithmPermitted(popoAlgId)) {
            String algoName;
            try {
                algoName = AlgorithmUtil.getSignatureAlgoName(popoAlgId);
            } catch (NoSuchAlgorithmException ex) {
                algoName = popoAlgId.getAlgorithm().getId();
            }
            LOG.error("POPO signature algorithm {} not permitted", algoName);
            return false;
        }

        try {
            PublicKey publicKey = securityFactory.generatePublicKey(
                    certRequest.getCertTemplate().getPublicKey());
            ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(publicKey);
            return certRequest.isValidSigningKeyPOP(cvp);
        } catch (InvalidKeyException | IllegalStateException | CRMFException ex) {
            LogUtil.error(LOG, ex);
        }
        return false;
    } // method verifyPopo

    @Override
    protected CmpControl getCmpControl() {
        X509Ca ca = getCa();
        if (ca != null) {
            String name = ca.getCaInfo().getCmpControlName();
            if (name != null) {
                return caManager.getCmpControlObject(name);
            }
        }

        throw new IllegalStateException(
                "should not happen, no CMP control is defined for CA " + caName);
    }

    private boolean isCertProfilePermitted(final CmpRequestorInfo requestor,
            final String certprofile) {
        Set<String> profiles = requestor.getCaHasRequestor().getProfiles();
        if (profiles != null) {
            if (profiles.contains("all") || profiles.contains(certprofile)) {
                return true;
            }
        }

        return false;
    }

    private void checkPermission(final X509Certificate requestorCert,
            final Permission requiredPermission) throws OperationException {
        CmpRequestorInfo requestor = getRequestor(requestorCert);
        if (requestor == null) {
            throw new OperationException(ErrorCode.NOT_PERMITTED);
        }

        try {
            checkPermission(requestor, requiredPermission);
        } catch (InsuffientPermissionException ex) {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION, ex.getMessage());
        }
    }

    private void checkPermission(final CmpRequestorInfo requestor,
            final Permission requiredPermission) throws InsuffientPermissionException {
        X509Ca ca = getCa();
        Set<Permission> permissions = ca.getCaInfo().getPermissions();
        boolean granted = false;
        if (permissions.contains(Permission.ALL) || permissions.contains(requiredPermission)) {
            Set<Permission> tmpPermissions = requestor.getCaHasRequestor().getPermissions();
            if (tmpPermissions.contains(Permission.ALL)
                    || tmpPermissions.contains(requiredPermission)) {
                granted = true;
            }
        }

        if (granted) {
            return;
        }

        String msg = requiredPermission.getPermission() + " is not allowed";
        LOG.warn(msg);
        throw new InsuffientPermissionException(msg);
    } // method checkPermission

    private String getSystemInfo(final CmpRequestorInfo requestor,
            final Set<Integer> acceptVersions) throws OperationException {
        X509Ca ca = getCa();
        StringBuilder sb = new StringBuilder(2000);
        // current maximal support version is 2
        int version = 2;
        if (CollectionUtil.isNonEmpty(acceptVersions) && !acceptVersions.contains(version)) {
            Integer ver = null;
            for (Integer m : acceptVersions) {
                if (m < version) {
                    ver = m;
                }
            }

            if (ver == null) {
                throw new OperationException(ErrorCode.BAD_REQUEST,
                    "none of versions " + acceptVersions + " is supported");
            } else {
                version = ver;
            }
        }

        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
        sb.append("<systemInfo version=\"").append(version).append("\">");
        if (version == 2) {
            // CACert
            sb.append("<CACert>");
            sb.append(Base64.toBase64String(ca.getCaInfo().getCertificate().getEncodedCert()));
            sb.append("</CACert>");

            // Profiles
            Set<String> requestorProfiles = requestor.getCaHasRequestor().getProfiles();

            Set<String> supportedProfileNames = new HashSet<>();
            Set<String> caProfileNames = ca.getCaManager().getCertprofilesForCa(
                    ca.getCaInfo().getName());
            for (String caProfileName : caProfileNames) {
                if (requestorProfiles.contains("all")
                        || requestorProfiles.contains(caProfileName)) {
                    supportedProfileNames.add(caProfileName);
                }
            }

            if (CollectionUtil.isNonEmpty(supportedProfileNames)) {
                sb.append("<certprofiles>");
                for (String name : supportedProfileNames) {
                    CertprofileEntry entry = ca.getCaManager().getCertprofile(name);
                    if (entry.isFaulty()) {
                        continue;
                    }

                    sb.append("<certprofile>");
                    sb.append("<name>").append(name).append("</name>");
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
    } // method getSystemInfo

    @Override
    protected ConcurrentContentSigner getSigner() {
        String name = getResponderName();
        return caManager.getCmpResponderWrapper(name).getSigner();
    }

    @Override
    protected GeneralName getSender() {
        return caManager.getCmpResponderWrapper(getResponderName()).getSubjectAsGeneralName();
    }

    @Override
    protected boolean intendsMe(final GeneralName requestRecipient) {
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
    } // method intendsMe

    @Override
    protected CmpRequestorInfo getRequestor(final X500Name requestorSender) {
        return getCa().getRequestor(requestorSender);
    }

    @Override
    protected CmpRequestorInfo getRequestor(final X509Certificate requestorCert) {
        return getCa().getRequestor(requestorCert);
    }

    private PKIBody cmpEnrollCert(final PKIMessage request, final PKIHeaderBuilder respHeader,
            final CmpControl cmpControl, final PKIHeader reqHeader, final PKIBody reqBody,
            final CmpRequestorInfo requestor, final String user, final ASN1OctetString tid,
            final AuditEvent auditEvent) throws InsuffientPermissionException {
        long confirmWaitTime = cmpControl.getConfirmWaitTime();
        if (confirmWaitTime < 0) {
            confirmWaitTime *= -1;
        }
        confirmWaitTime *= 1000; // second to millisecond

        PKIBody respBody;

        int type = reqBody.getType();
        switch (type) {
        case PKIBody.TYPE_CERT_REQ:
            addAutitEventType(auditEvent, "CERT_REQ");
            checkPermission(requestor, Permission.ENROLL_CERT);
            respBody = processCr(request, requestor, user, tid, reqHeader,
                    CertReqMessages.getInstance(reqBody.getContent()), cmpControl, auditEvent);
            break;
        case PKIBody.TYPE_KEY_UPDATE_REQ:
            addAutitEventType(auditEvent, "KEY_UPDATE");
            checkPermission(requestor, Permission.KEY_UPDATE);
            respBody = processKur(request, requestor, user, tid, reqHeader,
                    CertReqMessages.getInstance(reqBody.getContent()), cmpControl, auditEvent);
            break;
        case PKIBody.TYPE_P10_CERT_REQ:
            addAutitEventType(auditEvent, "CERT_REQ");
            checkPermission(requestor, Permission.ENROLL_CERT);
            respBody = processP10cr(request, requestor, user, tid, reqHeader,
                    CertificationRequest.getInstance(reqBody.getContent()), cmpControl, auditEvent);
            break;
        case PKIBody.TYPE_CROSS_CERT_REQ:
            addAutitEventType(auditEvent, "CROSS_CERT_REQ");
            checkPermission(requestor, Permission.CROSS_CERT_ENROLL);
            respBody = processCcp(request, requestor, user, tid, reqHeader,
                    CertReqMessages.getInstance(reqBody.getContent()), cmpControl, auditEvent);
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
            tv = new InfoTypeAndValue(CMPObjectIdentifiers.it_confirmWaitTime,
                    new ASN1GeneralizedTime(
                            new Date(System.currentTimeMillis() + confirmWaitTime)));
        }

        respHeader.setGeneralInfo(tv);
        return respBody;
    } // method cmpEnrollCert

    private PKIBody cmpRevokeOrUnrevokeOrRemoveCertificates(final PKIMessage request,
            final PKIHeaderBuilder respHeader, final CmpControl cmpControl,
            final PKIHeader reqHeader, final PKIBody reqBody, final CmpRequestorInfo requestor,
            final String user, final ASN1OctetString tid, final AuditEvent auditEvent) {
        Permission requiredPermission = null;
        boolean allRevdetailsOfSameType = true;

        RevReqContent rr = RevReqContent.getInstance(reqBody.getContent());
        RevDetails[] revContent = rr.toRevDetailsArray();

        int len = revContent.length;
        for (int i = 0; i < len; i++) {
            RevDetails revDetails = revContent[i];
            Extensions crlDetails = revDetails.getCrlEntryDetails();
            int reasonCode = CrlReason.UNSPECIFIED.getCode();
            if (crlDetails != null) {
                ASN1ObjectIdentifier extId = Extension.reasonCode;
                ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
                if (extValue != null) {
                    reasonCode = ASN1Enumerated.getInstance(extValue).getValue().intValue();
                }
            }

            if (reasonCode == XiSecurityConstants.CMP_CRL_REASON_REMOVE) {
                if (requiredPermission == null) {
                    addAutitEventType(auditEvent, "CERT_REMOVE");
                    requiredPermission = Permission.REMOVE_CERT;
                } else if (requiredPermission != Permission.REMOVE_CERT) {
                    allRevdetailsOfSameType = false;
                    break;
                }
            } else if (reasonCode == CrlReason.REMOVE_FROM_CRL.getCode()) {
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
        } // end for

        if (!allRevdetailsOfSameType) {
            ErrorMsgContent emc = new ErrorMsgContent(
                    new PKIStatusInfo(PKIStatus.rejection,
                    new PKIFreeText("not all revDetails are of the same type"),
                    new PKIFailureInfo(PKIFailureInfo.badRequest)));

            return new PKIBody(PKIBody.TYPE_ERROR, emc);
        } else {
            try {
                checkPermission(requestor, requiredPermission);
            } catch (InsuffientPermissionException ex) {
                auditEvent.setStatus(AuditStatus.FAILED);
                auditEvent.addEventData("message", "NOT_PERMITTED");
                return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.notAuthorized,
                        null);
            }
            return revokeOrUnrevokeOrRemoveCertificates(request, rr, auditEvent,
                    requiredPermission);
        }
    } // method cmpRevokeOrUnrevokeOrRemoveCertificates

    private PKIBody cmpGeneralMsg(final PKIHeaderBuilder respHeader, final CmpControl cmpControl,
            final PKIHeader reqHeader, final PKIBody reqBody, final CmpRequestorInfo requestor,
            final String user, final ASN1OctetString tid, final AuditEvent auditEvent)
    throws InsuffientPermissionException {
        GenMsgContent genMsgBody = GenMsgContent.getInstance(reqBody.getContent());
        InfoTypeAndValue[] itvs = genMsgBody.toInfoTypeAndValueArray();

        InfoTypeAndValue itv = null;
        if (itvs != null && itvs.length > 0) {
            for (InfoTypeAndValue entry : itvs) {
                String itvType = entry.getInfoType().getId();
                if (KNOWN_GENMSG_IDS.contains(itvType)) {
                    itv = entry;
                    break;
                }
            }
        }

        if (itv == null) {
            String statusMessage = "PKIBody type " + PKIBody.TYPE_GEN_MSG
                    + " is only supported with the sub-types " + KNOWN_GENMSG_IDS.toString();
            return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                    statusMessage);
        }

        InfoTypeAndValue itvResp = null;
        ASN1ObjectIdentifier infoType = itv.getInfoType();

        int failureInfo;
        try {
            X509Ca ca = getCa();
            if (CMPObjectIdentifiers.it_currentCRL.equals(infoType)) {
                addAutitEventType(auditEvent, "CRL_DOWNLOAD");
                checkPermission(requestor, Permission.GET_CRL);
                CertificateList crl = ca.getCurrentCrl();

                if (itv.getInfoValue() == null) { // as defined in RFC 4210
                    crl = ca.getCurrentCrl();
                } else {
                    // xipki extension
                    ASN1Integer crlNumber = ASN1Integer.getInstance(itv.getInfoValue());
                    crl = ca.getCrl(crlNumber.getPositiveValue());
                }

                if (crl == null) {
                    String statusMessage = "no CRL is available";
                    return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.systemFailure,
                            statusMessage);
                }

                itvResp = new InfoTypeAndValue(infoType, crl);
            } else if (ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.equals(infoType)) {
                ASN1Encodable asn1 = itv.getInfoValue();
                ASN1Integer asn1Code = null;
                ASN1Encodable reqValue = null;

                try {
                    ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
                    asn1Code = ASN1Integer.getInstance(seq.getObjectAt(0));
                    if (seq.size() > 1) {
                        reqValue = seq.getObjectAt(1);
                    }
                } catch (IllegalArgumentException ex) {
                    String statusMessage = "invalid value of the InfoTypeAndValue for "
                            + ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId();
                    return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                            statusMessage);
                }

                ASN1Encodable respValue;

                int action = asn1Code.getPositiveValue().intValue();
                switch (action) {
                case XiSecurityConstants.CMP_ACTION_GEN_CRL:
                    addAutitEventType(auditEvent, "CRL_GEN_ONDEMAND");
                    checkPermission(requestor, Permission.GEN_CRL);
                    X509CRL tmpCrl = ca.generateCrlOnDemand(auditEvent);
                    if (tmpCrl == null) {
                        String statusMessage = "CRL generation is not activated";
                        return buildErrorMsgPkiBody(PKIStatus.rejection,
                                PKIFailureInfo.systemFailure, statusMessage);
                    } else {
                        respValue = CertificateList.getInstance(tmpCrl.getEncoded());
                    }
                    break;
                case XiSecurityConstants.CMP_ACTION_GET_CRL_WITH_SN:
                    addAutitEventType(auditEvent, "CRL_DOWNLOAD_WITH_SN");
                    checkPermission(requestor, Permission.GET_CRL);

                    ASN1Integer crlNumber = ASN1Integer.getInstance(reqValue);
                    respValue = ca.getCrl(crlNumber.getPositiveValue());
                    if (respValue == null) {
                        String statusMessage = "no CRL is available";
                        return buildErrorMsgPkiBody(PKIStatus.rejection,
                                PKIFailureInfo.systemFailure, statusMessage);
                    }
                    break;
                case XiSecurityConstants.CMP_ACTION_GET_CAINFO:
                    addAutitEventType(auditEvent, "GET_SYSTEMINFO");
                    Set<Integer> acceptVersions = new HashSet<>();
                    if (reqValue != null) {
                        ASN1Sequence seq = DERSequence.getInstance(reqValue);
                        int size = seq.size();
                        for (int i = 0; i < size; i++) {
                            ASN1Integer ai = ASN1Integer.getInstance(seq.getObjectAt(i));
                            acceptVersions.add(ai.getPositiveValue().intValue());
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
                    return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                            statusMessage);
                } // end switch (action)

                ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(asn1Code);
                if (respValue != null) {
                    vec.add(respValue);
                }
                itvResp = new InfoTypeAndValue(infoType, new DERSequence(vec));
            }

            GenRepContent genRepContent = new GenRepContent(itvResp);
            return new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
        } catch (OperationException ex) {
            failureInfo = getPKiFailureInfo(ex);
            ErrorCode code = ex.getErrorCode();

            String errorMessage;
            switch (code) {
            case DATABASE_FAILURE:
            case SYSTEM_FAILURE:
                errorMessage = code.name();
                break;
            default:
                errorMessage = code.name() + ": " + ex.getErrorMessage();
                break;
            } // end switch code

            return buildErrorMsgPkiBody(PKIStatus.rejection, failureInfo, errorMessage);
        } catch (CRLException ex) {
            String statusMessage = "CRLException: " + ex.getMessage();
            return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.systemFailure,
                    statusMessage);
        }
    } // method cmpGeneralMsg

    /**
     * @since 2.1.0
     */
    public CertificateList getCrl(final X509Certificate requestorCert, final BigInteger crlNumber,
            final AuditEvent auditEvent) throws OperationException {
        addAutitEventType(auditEvent, "CRL_DOWNLOAD");
        checkPermission(requestorCert, Permission.GET_CRL);

        X509Ca ca = getCa();
        return (crlNumber == null) ? ca.getCurrentCrl() : ca.getCrl(crlNumber);
    }

    /**
     * @since 2.1.0
     */
    public X509CRL generateCrlOnDemand(final X509Certificate requestorCert,
            final AuditEvent auditEvent) throws OperationException {
        addAutitEventType(auditEvent, "CRL_GEN_ONDEMAND");
        checkPermission(requestorCert, Permission.GEN_CRL);

        X509Ca ca = getCa();
        return ca.generateCrlOnDemand(auditEvent);
    }

    /**
     * @since 2.1.0
     */
    public X509Cert generateCert(final X509Certificate requestorCert, final byte[] encodedCsr,
            final String profileName, final Date notBefore, final Date notAfter, final String user,
            final RequestType reqType, final AuditEvent auditEvent)
    throws OperationException {
        addAutitEventType(auditEvent, "CERT_REQ");

        CmpRequestorInfo requestor = getRequestor(requestorCert);
        if (requestor == null) {
            throw new OperationException(ErrorCode.NOT_PERMITTED);
        }

        try {
            checkPermission(requestor, Permission.ENROLL_CERT);
        } catch (InsuffientPermissionException ex) {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION, ex.getMessage());
        }

        CertificationRequest csr = CertificationRequest.getInstance(encodedCsr);
        if (!securityFactory.verifyPopo(csr, getCmpControl().getPopoAlgoValidator())) {
            LOG.warn("could not validate POP for the pkcs#10 requst");
            throw new OperationException(ErrorCode.BAD_POP);
        }

        CertificationRequestInfo certTemp = csr.getCertificationRequestInfo();

        X500Name subject = certTemp.getSubject();
        auditEvent.addEventData("req-subject", X509Util.getRfc4519Name(subject));

        SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();
        auditEvent.addEventData("certprofile", profileName);

        if (!isCertProfilePermitted(requestor, profileName)) {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "certProfile " + profileName + " is not allowed");
        }

        Extensions extensions = CaUtil.getExtensions(certTemp);
        CertTemplateData certTemplate = new CertTemplateData(subject, publicKeyInfo,
                notBefore, notAfter, extensions, profileName);

        X509Ca ca = getCa();
        X509CertificateInfo certInfo = ca.generateCertificate(certTemplate, requestor.isRa(),
                requestor, user, reqType, null);
        certInfo.setRequestor(requestor);
        certInfo.setUser(user);

        auditEvent.addEventData("req-subject", certInfo.getCert().getSubject());

        if (ca.getCaInfo().isSaveRequest()) {
            long dbId = ca.addRequest(encodedCsr);
            ca.addRequestCert(dbId, certInfo.getCert().getCertId());
        }
        auditEvent.setStatus(AuditStatus.SUCCESSFUL);

        return certInfo.getCert();
    }

    /**
     * @since 2.1.0
     */
    public void revokeCert(final X509Certificate requestorCert, final BigInteger serialNumber,
            final CrlReason reason, final Date invalidityDate, final AuditEvent auditEvent)
    throws OperationException {
        String eventType;
        Permission permission;

        if (reason == CrlReason.REMOVE_FROM_CRL) {
            eventType = "CERT_UNREVOKE";
            permission = Permission.UNREVOKE_CERT;
        } else {
            eventType = "CERT_REVOKE";
            permission = Permission.REVOKE_CERT;
        }
        addAutitEventType(auditEvent, eventType);
        checkPermission(requestorCert, permission);

        auditEvent.addEventData("serialNumber", LogUtil.formatCsn(serialNumber));

        X509Ca ca = getCa();
        Object returnedObj;
        if (Permission.UNREVOKE_CERT == permission) {
            // unrevoke
            returnedObj = ca.unrevokeCertificate(serialNumber);
        } else {
            // revoke
            auditEvent.addEventData("reason", reason.getDescription());
            if (invalidityDate != null) {
                String value = DateUtil.toUtcTimeyyyyMMddhhmmss(invalidityDate);
                auditEvent.addEventData("invalidityDate", value);
            }

            returnedObj = ca.revokeCertificate(serialNumber, reason, invalidityDate);
        } // end if (permission)

        if (returnedObj == null) {
            throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
        }

        auditEvent.setStatus(AuditStatus.SUCCESSFUL);
    }

    /**
     * @since 2.1.0
     */
    public void removeCert(final X509Certificate requestorCert, final BigInteger serialNumber,
            final AuditEvent auditEvent) throws OperationException {
        addAutitEventType(auditEvent, "REMOVE_CERT");
        checkPermission(requestorCert, Permission.REMOVE_CERT);

        auditEvent.addEventData("serialNumber", LogUtil.formatCsn(serialNumber));

        X509Ca ca = getCa();
        X509CertWithDbId returnedObj = ca.removeCertificate(serialNumber);
        if (returnedObj == null) {
            throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
        }

        auditEvent.setStatus(AuditStatus.SUCCESSFUL);
    }

    private static PKIBody buildErrorMsgPkiBody(final PKIStatus pkiStatus, final int failureInfo,
            final String statusMessage) {
        PKIFreeText pkiStatusMsg = (statusMessage == null) ? null : new PKIFreeText(statusMessage);
        ErrorMsgContent emc = new ErrorMsgContent(
                new PKIStatusInfo(pkiStatus, pkiStatusMsg, new PKIFailureInfo(failureInfo)));
        return new PKIBody(PKIBody.TYPE_ERROR, emc);
    }

    private static void addAutitEventType(final AuditEvent auditEvent, final String eventType) {
        auditEvent.addEventData("eventType", eventType);
    }

    private CertResponse buildErrorCertResponse(ASN1Integer certReqId, int pkiFailureInfo,
            String msg, AuditChildEvent auditChildEvent) {
        return buildErrorCertResponse(certReqId, pkiFailureInfo, msg, msg, auditChildEvent);
    }

    private CertResponse buildErrorCertResponse(ASN1Integer certReqId, int pkiFailureInfo,
            String msg, String pkiStatusText, AuditChildEvent auditChildEvent) {
        auditChildEvent.setStatus(AuditStatus.FAILED);
        auditChildEvent.addEventData("message", msg);
        return new CertResponse(certReqId,
                generateCmpRejectionStatus(pkiFailureInfo, pkiStatusText));
    }

}
