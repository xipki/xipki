/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.server.impl.cmp;

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
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
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
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.InsuffientPermissionException;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.api.X509CertWithDbId;
import org.xipki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.ca.server.impl.CaAuditConstants;
import org.xipki.ca.server.impl.CaManagerImpl;
import org.xipki.ca.server.impl.CertTemplateData;
import org.xipki.ca.server.impl.X509Ca;
import org.xipki.ca.server.impl.store.X509CertWithRevocationInfo;
import org.xipki.ca.server.impl.util.CaUtil;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.PermissionConstants;
import org.xipki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.cmp.CmpUtf8Pairs;
import org.xipki.cmp.CmpUtil;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.util.Base64;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.CrlReason;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.XiSecurityConstants;
import org.xipki.security.util.AlgorithmUtil;

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
                    serialNumber = remainingCert.cert().cert().getSerialNumber();
                    ca.revokeCertificate(serialNumber, CrlReason.CESSATION_OF_OPERATION,
                            invalidityDate, CaAuditConstants.MSGID_CA_routine);
                } catch (Throwable th) {
                    LOG.error("could not revoke certificate (CA={}, serialNumber={}): {}",
                            ca.caInfo().ident(), LogUtil.formatCsn(serialNumber),
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
        KNOWN_GENMSG_IDS.add(ObjectIdentifiers.id_xipki_cmp_cacerts.getId());
    }

    public X509CaCmpResponder(final CaManagerImpl caManager, final String caName) {
        super(caManager.securityFactory());

        this.caManager = caManager;
        this.pendingCertPool = new PendingCertificatePool();
        this.caName = caName;

        PendingPoolCleaner pendingPoolCleaner = new PendingPoolCleaner();
        caManager.scheduledThreadPoolExecutor().scheduleAtFixedRate(pendingPoolCleaner, 10, 10,
                TimeUnit.MINUTES);
    }

    public X509Ca getCa() {
        try {
            return caManager.x509Ca(caName);
        } catch (CaMgmtException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean isOnService() {
        if (!super.isOnService()) {
            return false;
        }

        if (CaStatus.ACTIVE != getCa().caInfo().status()) {
            return false;
        }

        return true;
    }

    public HealthCheckResult healthCheck() {
        HealthCheckResult result = getCa().healthCheck();

        boolean healthy = result.isHealthy();

        boolean responderHealthy = caManager.cmpResponderWrapper(
                getResponderName()).signer().isHealthy();
        healthy &= responderHealthy;

        HealthCheckResult responderHealth = new HealthCheckResult("Responder");
        responderHealth.setHealthy(responderHealthy);
        result.addChildCheck(responderHealth);

        result.setHealthy(healthy);
        return result;
    }

    public String getResponderName() {
        return getCa().caInfo().responderName();
    }

    @Override
    protected PKIMessage processPkiMessage0(PKIMessage request, final RequestorInfo requestor,
            final ASN1OctetString tid, final GeneralPKIMessage message,
            final String msgId, final AuditEvent event) {
        if (!(requestor instanceof CmpRequestorInfo)) {
            throw new IllegalArgumentException(
                    "unknown requestor type " + requestor.getClass().getName());
        }

        CmpRequestorInfo tmpRequestor = (CmpRequestorInfo) requestor;
        event.addEventData(CaAuditConstants.NAME_requestor, tmpRequestor.ident().name());

        PKIHeader reqHeader = message.getHeader();
        PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
                reqHeader.getPvno().getValue().intValue(), getSender(), reqHeader.getSender());
        respHeader.setTransactionID(tid);
        ASN1OctetString senderNonce = reqHeader.getSenderNonce();
        if (senderNonce != null) {
            respHeader.setRecipNonce(senderNonce);
        }

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
                String eventType = null;
                if (PKIBody.TYPE_CERT_REQ == type) {
                    eventType = CaAuditConstants.TYPE_CMP_cr;
                } else if (PKIBody.TYPE_KEY_UPDATE_REQ == type) {
                    eventType = CaAuditConstants.TYPE_CMP_kur;
                } else if (PKIBody.TYPE_KEY_UPDATE_REQ == type) {
                    eventType = CaAuditConstants.TYPE_CMP_p10Cr;
                } else if (PKIBody.TYPE_CROSS_CERT_REQ == type) {
                    eventType = CaAuditConstants.TYPE_CMP_ccr;
                }

                if (eventType != null) {
                    event.addEventType(eventType);
                }
                respBody = cmpEnrollCert(request, respHeader, cmpControl, reqHeader, reqBody,
                        tmpRequestor, tid, msgId, event);
                break;
            case PKIBody.TYPE_CERT_CONFIRM:
                event.addEventType(CaAuditConstants.TYPE_CMP_certConf);
                CertConfirmContent certConf = (CertConfirmContent) reqBody.getContent();
                respBody = confirmCertificates(tid, certConf, msgId);
                break;
            case PKIBody.TYPE_REVOCATION_REQ:
                respBody = cmpUnRevokeRemoveCertificates(request, respHeader, cmpControl, reqHeader,
                        reqBody, tmpRequestor, msgId, event);
                break;
            case PKIBody.TYPE_CONFIRM:
                event.addEventType(CaAuditConstants.TYPE_CMP_pkiConf);
                respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
                break;
            case PKIBody.TYPE_GEN_MSG:
                respBody = cmpGeneralMsg(respHeader, cmpControl, reqHeader, reqBody, tmpRequestor,
                        tid, msgId, event);
                break;
            case PKIBody.TYPE_ERROR:
                event.addEventType(CaAuditConstants.TYPE_CMP_error);
                revokePendingCertificates(tid, msgId);
                respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
                break;
            default:
                event.addEventType("PKIBody." + type);
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
            org.xipki.cmp.PkiStatusInfo pkiStatus =
                    new org.xipki.cmp.PkiStatusInfo(
                            errorMsgContent.getPKIStatusInfo());

            if (pkiStatus.pkiFailureInfo() == PKIFailureInfo.systemFailure) {
                auditStatus = AuditStatus.FAILED;
            }
            event.setStatus(auditStatus);

            String statusString = pkiStatus.statusMessage();
            if (statusString != null) {
                event.addEventData(CaAuditConstants.NAME_message, statusString);
            }
        } else if (event.status() == null) {
            event.setStatus(AuditStatus.SUCCESSFUL);
        }

        return new PKIMessage(respHeader.build(), respBody);
    } // method processPKIMessage0

    /**
     * handle the PKI body with the choice {@code cr}.
     *
     */
    private PKIBody processCr(final PKIMessage request, final CmpRequestorInfo requestor,
            final ASN1OctetString tid, final PKIHeader reqHeader,
            final CertReqMessages cr, final CmpControl cmpControl, final String msgId,
            final AuditEvent event) {
        CertRepMessage repMessage = processCertReqMessages(request, requestor, tid, reqHeader,
                cr, false, cmpControl, msgId, event);
        return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
    }

    private PKIBody processKur(final PKIMessage request, final CmpRequestorInfo requestor,
            final ASN1OctetString tid, final PKIHeader reqHeader,
            final CertReqMessages kur, final CmpControl cmpControl, final String msgId,
            final AuditEvent event) {
        CertRepMessage repMessage = processCertReqMessages(request, requestor, tid, reqHeader,
                kur, true, cmpControl, msgId, event);
        return new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, repMessage);
    }

    /**
     * handle the PKI body with the choice {@code cr}.
     *
     */
    private PKIBody processCcp(final PKIMessage request, final CmpRequestorInfo requestor,
            final ASN1OctetString tid, final PKIHeader reqHeader,
            final CertReqMessages cr, final CmpControl cmpControl, final String msgId,
            final AuditEvent event) {
        CertRepMessage repMessage = processCertReqMessages(request, requestor, tid, reqHeader,
                cr, false, cmpControl, msgId, event);
        return new PKIBody(PKIBody.TYPE_CROSS_CERT_REP, repMessage);
    }

    private CertRepMessage processCertReqMessages(final PKIMessage request,
            final CmpRequestorInfo requestor, final ASN1OctetString tid,
            final PKIHeader reqHeader, final CertReqMessages kur, final boolean keyUpdate,
            final CmpControl cmpControl, final String msgId, final AuditEvent event) {
        CmpRequestorInfo tmpRequestor = (CmpRequestorInfo) requestor;

        CertReqMsg[] certReqMsgs = kur.toCertReqMsgArray();
        final int n = certReqMsgs.length;

        Map<Integer, CertTemplateData> certTemplateDatas = new HashMap<>(n * 10 / 6);
        Map<Integer, CertResponse> certResponses = new HashMap<>(n * 10 / 6);
        Map<Integer, ASN1Integer> certReqIds = new HashMap<>(n * 10 / 6);

        // pre-process requests
        for (int i = 0; i < n; i++) {
            if (cmpControl.isGroupEnroll() && certTemplateDatas.size() != i) {
                // last certReqMsg cannot be used to enroll certificate
                break;
            }

            CertReqMsg reqMsg = certReqMsgs[i];
            CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);
            ASN1Integer certReqId = reqMsg.getCertReq().getCertReqId();
            certReqIds.put(i, certReqId);

            if (!req.hasProofOfPossession()) {
                certResponses.put(i, buildErrorCertResponse(certReqId, PKIFailureInfo.badPOP,
                        "no POP", null));
                continue;
            }

            if (!verifyPopo(req, tmpRequestor.isRa())) {
                LOG.warn("could not validate POP for request {}", certReqId.getValue());
                certResponses.put(i, buildErrorCertResponse(certReqId, PKIFailureInfo.badPOP,
                        "invalid POP", null));
                continue;
            }

            CmpUtf8Pairs keyvalues = CmpUtil.extract(reqMsg.getRegInfo());
            String certprofileName = (keyvalues == null) ? null
                    : keyvalues.value(CmpUtf8Pairs.KEY_CERT_PROFILE);
            if (certprofileName == null) {
                String msg = "no certificate profile";
                certResponses.put(i, buildErrorCertResponse(certReqId,
                        PKIFailureInfo.badCertTemplate, msg));
                continue;
            }
            certprofileName = certprofileName.toUpperCase();

            if (!tmpRequestor.isCertProfilePermitted(certprofileName)) {
                String msg = "certprofile " + certprofileName + " is not allowed";
                certResponses.put(i, buildErrorCertResponse(certReqId, PKIFailureInfo.notAuthorized,
                        msg));
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
                PKIStatusInfo tmpStatus = generateRejectionStatus(failStatus,
                        failureInfo.intValue(), msg);
                certResps[i] = new CertResponse(certReqId, tmpStatus);
            }

            return new CertRepMessage(null, certResps);
        }

        final int k = certTemplateDatas.size();
        List<CertTemplateData> certTemplateList = new ArrayList<>(k);
        List<ASN1Integer> certReqIdList = new ArrayList<>(k);
        Map<Integer, Integer> reqIndexToCertIndexMap = new HashMap<>(k * 10 / 6);

        for (int i = 0; i < n; i++) {
            if (!certTemplateDatas.containsKey(i)) {
                continue;
            }

            certTemplateList.add(certTemplateDatas.get(i));
            certReqIdList.add(certReqIds.get(i));
            reqIndexToCertIndexMap.put(i, certTemplateList.size() - 1);
        }

        List<CertResponse> generateCertResponses = generateCertificates(
                certTemplateList, certReqIdList, tmpRequestor, tid,
                keyUpdate, request, cmpControl, msgId, event);
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
            caPubs = new CMPCertificate[]{getCa().caInfo().certInCmpFormat()};
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
            final ASN1OctetString tid, final PKIHeader reqHeader,
            final CertificationRequest p10cr, final CmpControl cmpControl, final String msgId,
            final AuditEvent event) {
        // verify the POP first
        CertResponse certResp;
        ASN1Integer certReqId = new ASN1Integer(-1);

        boolean certGenerated = false;
        X509Ca ca = getCa();

        if (!securityFactory.verifyPopo(p10cr, getCmpControl().popoAlgoValidator())) {
            LOG.warn("could not validate POP for the pkcs#10 requst");
            certResp = buildErrorCertResponse(certReqId, PKIFailureInfo.badPOP, "invalid POP");
        } else {
            CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
            Extensions extensions = CaUtil.getExtensions(certTemp);

            X500Name subject = certTemp.getSubject();
            SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

            CmpUtf8Pairs keyvalues = CmpUtil.extract(reqHeader.getGeneralInfo());
            String certprofileName = null;
            Date notBefore = null;
            Date notAfter = null;

            if (keyvalues != null) {
                certprofileName = keyvalues.value(CmpUtf8Pairs.KEY_CERT_PROFILE);

                String str = keyvalues.value(CmpUtf8Pairs.KEY_NOT_BEFORE);
                if (str != null) {
                    notBefore = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
                }

                str = keyvalues.value(CmpUtf8Pairs.KEY_NOT_AFTER);
                if (str != null) {
                    notAfter = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
                }
            }

            if (certprofileName == null) {
                certResp = buildErrorCertResponse(certReqId, PKIFailureInfo.badCertTemplate,
                        "badCertTemplate", null);
            } else {
                certprofileName = certprofileName.toUpperCase();
                if (!requestor.isCertProfilePermitted(certprofileName)) {
                    String msg = "certprofile " + certprofileName + " is not allowed";
                    certResp = buildErrorCertResponse(certReqId,
                            PKIFailureInfo.notAuthorized, msg);
                } else {
                    CertTemplateData certTemplateData = new CertTemplateData(subject, publicKeyInfo,
                            notBefore, notAfter, extensions, certprofileName);

                    certResp = generateCertificates(Arrays.asList(certTemplateData),
                            Arrays.asList(certReqId), requestor, tid, false, request,
                            cmpControl, msgId, event).get(0);
                    certGenerated = true;
                }
            }
        }

        CMPCertificate[] caPubs = null;
        if (certGenerated && cmpControl.isSendCaCert()) {
            caPubs = new CMPCertificate[]{ca.caInfo().certInCmpFormat()};
        }
        CertRepMessage repMessage = new CertRepMessage(caPubs, new CertResponse[]{certResp});

        return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
    } // method processP10cr

    private List<CertResponse> generateCertificates(
            final List<CertTemplateData> certTemplates, final List<ASN1Integer> certReqIds,
            final CmpRequestorInfo requestor, final ASN1OctetString tid,
            final boolean keyUpdate, final PKIMessage request, CmpControl cmpControl,
            final String msgId, final AuditEvent event) {
        X509Ca ca = getCa();

        final int n = certTemplates.size();
        List<CertResponse> ret = new ArrayList<>(n);

        if (cmpControl.isGroupEnroll()) {
            try {
                List<X509CertificateInfo> certInfos;
                if (keyUpdate) {
                    certInfos = ca.regenerateCertificates(certTemplates,
                            requestor, RequestType.CMP, tid.getOctets(), msgId);
                } else {
                    certInfos = ca.generateCertificates(certTemplates, requestor,
                            RequestType.CMP, tid.getOctets(), msgId);
                }

                // save the request
                Long reqDbId = null;
                if (ca.caInfo().isSaveRequest()) {
                    try {
                        byte[] encodedRequest = request.getEncoded();
                        reqDbId = ca.addRequest(encodedRequest);
                    } catch (Exception ex) {
                        LOG.warn("could not save request");
                    }
                }

                for (int i = 0; i < n; i++) {
                    X509CertificateInfo certInfo = certInfos.get(i);
                    ret.add(postProcessCertInfo(certReqIds.get(i), certInfo, tid, cmpControl));
                    if (reqDbId != null) {
                        ca.addRequestCert(reqDbId, certInfo.cert().certId());
                    }
                }
            } catch (OperationException ex) {
                for (int i = 0; i < n; i++) {
                    ret.add(postProcessException(certReqIds.get(i), ex));
                }
            }
        } else {
            Long reqDbId = null;
            boolean savingRequestFailed = false;

            for (int i = 0; i < n; i++) {
                CertTemplateData certTemplate = certTemplates.get(i);
                ASN1Integer certReqId = certReqIds.get(i);

                X509CertificateInfo certInfo;
                try {
                    if (keyUpdate) {
                        certInfo = ca.regenerateCertificate(certTemplate,
                                requestor, RequestType.CMP, tid.getOctets(), msgId);
                    } else {
                        certInfo = ca.generateCertificate(certTemplate, requestor,
                                RequestType.CMP, tid.getOctets(), msgId);
                    }

                    if (ca.caInfo().isSaveRequest()) {
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
                            ca.addRequestCert(reqDbId, certInfo.cert().certId());
                        }
                    }

                    ret.add(postProcessCertInfo(certReqId, certInfo, tid, cmpControl));
                } catch (OperationException ex) {
                    ret.add(postProcessException(certReqId, ex));
                }
            }
        }

        return ret;
    } // method generateCertificates

    private CertResponse postProcessCertInfo(ASN1Integer certReqId, X509CertificateInfo certInfo,
            ASN1OctetString tid, CmpControl cmpControl) {
        if (cmpControl.isConfirmCert()) {
            pendingCertPool.addCertificate(tid.getOctets(), certReqId.getPositiveValue(), certInfo,
                System.currentTimeMillis() + cmpControl.confirmWaitTimeMs());
        }

        String warningMsg = certInfo.warningMessage();

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

        CertOrEncCert cec = new CertOrEncCert(
                CMPCertificate.getInstance(certInfo.cert().encodedCert()));
        CertifiedKeyPair kp = new CertifiedKeyPair(cec);
        return new CertResponse(certReqId, statusInfo, kp, null);
    }

    private PKIBody unRevokeRemoveCertificates(final PKIMessage request, final RevReqContent rr,
            final int permission, final CmpControl cmpControl, final String msgId) {
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
                X500Name caSubject = getCa().caInfo().certificate().subjectAsX500Name();

                if (issuer == null) {
                    return buildErrorMsgPkiBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate, "issuer is not present");
                }

                if (!issuer.equals(caSubject)) {
                    return buildErrorMsgPkiBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate, "issuer does not target at the CA");
                }

                if (serialNumber == null) {
                    return buildErrorMsgPkiBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate, "serialNumber is not present");
                }

                if (certDetails.getSigningAlg() != null
                        || certDetails.getValidity() != null
                        || certDetails.getSubject() != null
                        || certDetails.getPublicKey() != null
                        || certDetails.getIssuerUID() != null
                        || certDetails.getSubjectUID() != null) {
                    return buildErrorMsgPkiBody(PKIStatus.rejection,
                            PKIFailureInfo.badCertTemplate,
                            "only version, issuer and serialNumber in RevDetails.certDetails are "
                            + "allowed, but more is specified");
                }

                if (certDetails.getExtensions() == null) {
                    if (cmpControl.isRrAkiRequired()) {
                        return buildErrorMsgPkiBody(PKIStatus.rejection,
                                PKIFailureInfo.badCertTemplate, "issuer's AKI not present");
                    }
                } else {
                    Extensions exts = certDetails.getExtensions();
                    ASN1ObjectIdentifier[] oids = exts.getCriticalExtensionOIDs();
                    if (oids != null) {
                        for (ASN1ObjectIdentifier oid : oids) {
                            if (!Extension.authorityKeyIdentifier.equals(oid)) {
                                return buildErrorMsgPkiBody(PKIStatus.rejection,
                                        PKIFailureInfo.badCertTemplate,
                                        "unknown critical extension " + oid.getId());
                            }
                        }
                    }

                    Extension ext = exts.getExtension(Extension.authorityKeyIdentifier);
                    if (ext == null) {
                        return buildErrorMsgPkiBody(PKIStatus.rejection,
                                PKIFailureInfo.badCertTemplate, "issuer's AKI not present");
                    } else {
                        AuthorityKeyIdentifier aki =
                                AuthorityKeyIdentifier.getInstance(ext.getParsedValue());

                        if (aki.getKeyIdentifier() == null) {
                            return buildErrorMsgPkiBody(PKIStatus.rejection,
                                    PKIFailureInfo.badCertTemplate, "issuer's AKI not present");
                        }

                        boolean issuerMatched = true;

                        byte[] caSki = getCa().caInfo().certificate()
                                .subjectKeyIdentifier();
                        if (!Arrays.equals(caSki, aki.getKeyIdentifier())) {
                            issuerMatched = false;
                        }

                        if (issuerMatched && aki.getAuthorityCertSerialNumber() != null) {
                            BigInteger caSerial = getCa().caInfo().serialNumber();
                            if (!caSerial.equals(aki.getAuthorityCertSerialNumber())) {
                                issuerMatched = false;
                            }
                        }

                        if (issuerMatched && aki.getAuthorityCertIssuer() != null) {
                            GeneralName[] names = aki.getAuthorityCertIssuer().getNames();
                            for (GeneralName name : names) {
                                if (name.getTagNo() != GeneralName.directoryName) {
                                    issuerMatched = false;
                                    break;
                                }

                                if (!caSubject.equals(name.getName())) {
                                    issuerMatched = false;
                                    break;
                                }
                            }
                        }

                        if (!issuerMatched) {
                            return buildErrorMsgPkiBody(PKIStatus.rejection,
                                    PKIFailureInfo.badCertTemplate,
                                    "issuer does not target at the CA");
                        }
                    }
                }
            } catch (IllegalArgumentException ex) {
                return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                        "the request is not invalid");
            }
        } // end for

        byte[] encodedRequest = null;
        if (getCa().caInfo().isSaveRequest()) {
            try {
                encodedRequest = request.getEncoded();
            } catch (IOException ex) {
                LOG.warn("could not encode request");
            }
        }

        Long reqDbId = null;

        for (int i = 0; i < n; i++) {
            RevDetails revDetails = revContent[i];

            CertTemplate certDetails = revDetails.getCertDetails();
            ASN1Integer serialNumber = certDetails.getSerialNumber();
            // serialNumber is not null due to the check in the previous for-block.

            X500Name caSubject = getCa().caInfo().certificate().subjectAsX500Name();
            BigInteger snBigInt = serialNumber.getPositiveValue();
            CertId certId = new CertId(new GeneralName(caSubject), serialNumber);

            PKIStatusInfo status;

            try {
                Object returnedObj = null;
                Long certDbId = null;
                X509Ca ca = getCa();
                if (PermissionConstants.UNREVOKE_CERT == permission) {
                    // unrevoke
                    returnedObj = ca.unrevokeCertificate(snBigInt, msgId);
                    if (returnedObj != null) {
                        certDbId = ((X509CertWithDbId) returnedObj).certId();
                    }
                } else if (PermissionConstants.REMOVE_CERT == permission) {
                    // remove
                    returnedObj = ca.removeCertificate(snBigInt, msgId);
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

                    returnedObj = ca.revokeCertificate(snBigInt, reason, invalidityDate, msgId);
                    if (returnedObj != null) {
                        certDbId = ((X509CertWithRevocationInfo) returnedObj).cert().certId();
                    }
                } // end if (permission)

                if (returnedObj == null) {
                    throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
                }

                if (certDbId != null && ca.caInfo().isSaveRequest()) {
                    if (reqDbId == null) {
                        reqDbId = ca.addRequest(encodedRequest);
                    }
                    ca.addRequestCert(reqDbId, certDbId);
                }
                status = new PKIStatusInfo(PKIStatus.granted);
            } catch (OperationException ex) {
                ErrorCode code = ex.errorCode();
                LOG.warn("{}, OperationException: code={}, message={}",
                        PermissionConstants.getTextForCode(permission),
                        code.name(), ex.errorMessage());
                String errorMessage;
                switch (code) {
                case DATABASE_FAILURE:
                case SYSTEM_FAILURE:
                    errorMessage = code.name();
                    break;
                default:
                    errorMessage = code.name() + ": " + ex.errorMessage();
                    break;
                } // end switch code

                int failureInfo = getPKiFailureInfo(ex);
                status = generateRejectionStatus(failureInfo, errorMessage);
            } // end try

            repContentBuilder.add(status, certId);
        } // end for

        return new PKIBody(PKIBody.TYPE_REVOCATION_REP, repContentBuilder.build());
    } // method revokeOrUnrevokeOrRemoveCertificates

    private CertResponse postProcessException(ASN1Integer certReqId, OperationException ex) {
        ErrorCode code = ex.errorCode();
        LOG.warn("generate certificate, OperationException: code={}, message={}",
                code.name(), ex.errorMessage());

        String errorMessage;
        switch (code) {
        case DATABASE_FAILURE:
        case SYSTEM_FAILURE:
            errorMessage = code.name();
            break;
        default:
            errorMessage = code.name() + ": " + ex.errorMessage();
            break;
        } // end switch code

        int failureInfo = getPKiFailureInfo(ex);
        return new CertResponse(certReqId, generateRejectionStatus(failureInfo, errorMessage));
    }

    private int getPKiFailureInfo(OperationException ex) {
        ErrorCode code = ex.errorCode();

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
            final CertConfirmContent certConf, final String msgId) {
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

            BigInteger serialNumber = certInfo.cert().cert().getSerialNumber();
            X509Ca ca = getCa();
            try {
                ca.revokeCertificate(serialNumber, CrlReason.CESSATION_OF_OPERATION, new Date(),
                        msgId);
            } catch (OperationException ex) {
                LogUtil.warn(LOG, ex,
                        "could not revoke certificate ca=" + ca.caInfo().ident()
                        + " serialNumber=" + LogUtil.formatCsn(serialNumber));
            }

            successful = false;
        }

        // all other certificates should be revoked
        if (revokePendingCertificates(transactionId, msgId)) {
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

    private boolean revokePendingCertificates(final ASN1OctetString transactionId,
            final String msgId) {
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
                ca.revokeCertificate(remainingCert.cert().cert().getSerialNumber(),
                    CrlReason.CESSATION_OF_OPERATION, invalidityDate, msgId);
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
        AlgorithmValidator algoValidator = getCmpControl().popoAlgoValidator();
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
        CmpControl control = getCa().cmpControl();
        if (control != null) {
            return control;
        }
        throw new IllegalStateException(
                "should not happen, no CMP control is defined for CA " + caName);
    }

    private void checkPermission(final CmpRequestorInfo requestor,
            final int requiredPermission) throws InsuffientPermissionException {
        X509Ca ca = getCa();
        int permission = ca.caInfo().permission();
        if (!PermissionConstants.contains(permission, requiredPermission)) {
            throw new InsuffientPermissionException(
                    "Permission " + PermissionConstants.getTextForCode(requiredPermission)
                    + "is not permitted");
        }

        requestor.assertPermitted(requiredPermission);
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
            sb.append(Base64.encodeToString(ca.caInfo().certificate().encodedCert()));
            sb.append("</CACert>");

            // CMP control
            sb.append("<cmpControl>");
            sb.append("<rrAkiRequired>").append(getCmpControl().isRrAkiRequired())
                .append("</rrAkiRequired>");
            sb.append("</cmpControl>");

            // Profiles
            Set<String> requestorProfiles = requestor.caHasRequestor().profiles();

            Set<String> supportedProfileNames = new HashSet<>();
            Set<String> caProfileNames = ca.caManager().getCertprofilesForCa(
                    ca.caInfo().ident().name());
            for (String caProfileName : caProfileNames) {
                if (requestorProfiles.contains("ALL")
                        || requestorProfiles.contains(caProfileName)) {
                    supportedProfileNames.add(caProfileName);
                }
            }

            if (CollectionUtil.isNonEmpty(supportedProfileNames)) {
                sb.append("<certprofiles>");
                for (String name : supportedProfileNames) {
                    CertprofileEntry entry = ca.caManager().getCertprofile(name);
                    if (entry.isFaulty()) {
                        continue;
                    }

                    sb.append("<certprofile>");
                    sb.append("<name>").append(name).append("</name>");
                    sb.append("<type>").append(entry.type()).append("</type>");
                    sb.append("<conf>");
                    String conf = entry.conf();
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
        return caManager.cmpResponderWrapper(name).signer();
    }

    @Override
    protected GeneralName getSender() {
        return caManager.cmpResponderWrapper(getResponderName()).subjectAsGeneralName();
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
                    caManager.cmpResponderWrapper(getResponderName()).subjectAsX500Name())) {
                return true;
            }
        }

        return false;
    } // method intendsMe

    @Override
    public CmpRequestorInfo getRequestor(final X500Name requestorSender) {
        return getCa().getRequestor(requestorSender);
    }

    @Override
    public CmpRequestorInfo getRequestor(final X509Certificate requestorCert) {
        return getCa().getRequestor(requestorCert);
    }

    private PKIBody cmpEnrollCert(final PKIMessage request, final PKIHeaderBuilder respHeader,
            final CmpControl cmpControl, final PKIHeader reqHeader, final PKIBody reqBody,
            final CmpRequestorInfo requestor, final ASN1OctetString tid,
            final String msgId, final AuditEvent event) throws InsuffientPermissionException {
        long confirmWaitTime = cmpControl.confirmWaitTime();
        if (confirmWaitTime < 0) {
            confirmWaitTime *= -1;
        }
        confirmWaitTime *= 1000; // second to millisecond

        PKIBody respBody;

        int type = reqBody.getType();
        switch (type) {
        case PKIBody.TYPE_CERT_REQ:
            checkPermission(requestor, PermissionConstants.ENROLL_CERT);
            respBody = processCr(request, requestor, tid, reqHeader,
                    CertReqMessages.getInstance(reqBody.getContent()), cmpControl, msgId, event);
            break;
        case PKIBody.TYPE_KEY_UPDATE_REQ:
            checkPermission(requestor, PermissionConstants.KEY_UPDATE);
            respBody = processKur(request, requestor, tid, reqHeader,
                    CertReqMessages.getInstance(reqBody.getContent()), cmpControl, msgId, event);
            break;
        case PKIBody.TYPE_P10_CERT_REQ:
            checkPermission(requestor, PermissionConstants.ENROLL_CERT);
            respBody = processP10cr(request, requestor, tid, reqHeader,
                    CertificationRequest.getInstance(reqBody.getContent()), cmpControl, msgId,
                    event);
            break;
        case PKIBody.TYPE_CROSS_CERT_REQ:
            checkPermission(requestor, PermissionConstants.ENROLL_CROSS);
            respBody = processCcp(request, requestor, tid, reqHeader,
                    CertReqMessages.getInstance(reqBody.getContent()), cmpControl, msgId, event);
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

    private PKIBody cmpUnRevokeRemoveCertificates(final PKIMessage request,
            final PKIHeaderBuilder respHeader, final CmpControl cmpControl,
            final PKIHeader reqHeader, final PKIBody reqBody, final CmpRequestorInfo requestor,
            final String msgId, final AuditEvent event) {
        Integer requiredPermission = null;
        boolean allRevdetailsOfSameType = true;

        RevReqContent rr = RevReqContent.getInstance(reqBody.getContent());
        RevDetails[] revContent = rr.toRevDetailsArray();

        int len = revContent.length;
        for (int i = 0; i < len; i++) {
            RevDetails revDetails = revContent[i];
            Extensions crlDetails = revDetails.getCrlEntryDetails();
            int reasonCode = CrlReason.UNSPECIFIED.code();
            if (crlDetails != null) {
                ASN1ObjectIdentifier extId = Extension.reasonCode;
                ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
                if (extValue != null) {
                    reasonCode = ASN1Enumerated.getInstance(extValue).getValue().intValue();
                }
            }

            if (reasonCode == XiSecurityConstants.CMP_CRL_REASON_REMOVE) {
                if (requiredPermission == null) {
                    event.addEventType(CaAuditConstants.TYPE_CMP_rr_remove);
                    requiredPermission = PermissionConstants.REMOVE_CERT;
                } else if (requiredPermission != PermissionConstants.REMOVE_CERT) {
                    allRevdetailsOfSameType = false;
                    break;
                }
            } else if (reasonCode == CrlReason.REMOVE_FROM_CRL.code()) {
                if (requiredPermission == null) {
                    event.addEventType(CaAuditConstants.TYPE_CMP_rr_unrevoke);
                    requiredPermission = PermissionConstants.UNREVOKE_CERT;
                } else if (requiredPermission != PermissionConstants.UNREVOKE_CERT) {
                    allRevdetailsOfSameType = false;
                    break;
                }
            } else {
                if (requiredPermission == null) {
                    event.addEventType(CaAuditConstants.TYPE_CMP_rr_revoke);
                    requiredPermission = PermissionConstants.REVOKE_CERT;
                } else if (requiredPermission != PermissionConstants.REVOKE_CERT) {
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
                event.setStatus(AuditStatus.FAILED);
                event.addEventData(CaAuditConstants.NAME_message, "NOT_PERMITTED");
                return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.notAuthorized,
                        null);
            }
            return unRevokeRemoveCertificates(request, rr, requiredPermission, cmpControl, msgId);
        }
    } // method cmpRevokeOrUnrevokeOrRemoveCertificates

    private PKIBody cmpGeneralMsg(final PKIHeaderBuilder respHeader, final CmpControl cmpControl,
            final PKIHeader reqHeader, final PKIBody reqBody, final CmpRequestorInfo requestor,
            final ASN1OctetString tid, final String msgId,
            final AuditEvent event) throws InsuffientPermissionException {
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
                event.addEventType(CaAuditConstants.TYPE_CMP_genm_currentCrl);
                checkPermission(requestor, PermissionConstants.GET_CRL);
                CertificateList crl = ca.getBcCurrentCrl();

                if (itv.getInfoValue() == null) { // as defined in RFC 4210
                    crl = ca.getBcCurrentCrl();
                } else {
                    // xipki extension
                    ASN1Integer crlNumber = ASN1Integer.getInstance(itv.getInfoValue());
                    crl = ca.getBcCrl(crlNumber.getPositiveValue());
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
                    event.addEventType(CaAuditConstants.TYPE_CMP_genm_genCrl);
                    checkPermission(requestor, PermissionConstants.GEN_CRL);
                    X509CRL tmpCrl = ca.generateCrlOnDemand(msgId);
                    if (tmpCrl == null) {
                        String statusMessage = "CRL generation is not activated";
                        return buildErrorMsgPkiBody(PKIStatus.rejection,
                                PKIFailureInfo.systemFailure, statusMessage);
                    } else {
                        respValue = CertificateList.getInstance(tmpCrl.getEncoded());
                    }
                    break;
                case XiSecurityConstants.CMP_ACTION_GET_CRL_WITH_SN:
                    event.addEventType(CaAuditConstants.TYPE_CMP_genm_crlForNumber);
                    checkPermission(requestor, PermissionConstants.GET_CRL);

                    ASN1Integer crlNumber = ASN1Integer.getInstance(reqValue);
                    respValue = ca.getBcCrl(crlNumber.getPositiveValue());
                    if (respValue == null) {
                        String statusMessage = "no CRL is available";
                        return buildErrorMsgPkiBody(PKIStatus.rejection,
                                PKIFailureInfo.systemFailure, statusMessage);
                    }
                    break;
                case XiSecurityConstants.CMP_ACTION_GET_CAINFO:
                    event.addEventType(CaAuditConstants.TYPE_CMP_genm_cainfo);
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
            } else if (ObjectIdentifiers.id_xipki_cmp_cacerts.equals(infoType)) {
                event.addEventType(CaAuditConstants.TYPE_CMP_genm_cacerts);
                CMPCertificate caCert = ca.caInfo().certInCmpFormat();
                itvResp = new InfoTypeAndValue(infoType, new DERSequence(caCert));
            }

            GenRepContent genRepContent = new GenRepContent(itvResp);
            return new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
        } catch (OperationException ex) {
            failureInfo = getPKiFailureInfo(ex);
            ErrorCode code = ex.errorCode();

            String errorMessage;
            switch (code) {
            case DATABASE_FAILURE:
            case SYSTEM_FAILURE:
                errorMessage = code.name();
                break;
            default:
                errorMessage = code.name() + ": " + ex.errorMessage();
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
    public CertificateList getCrl(final CmpRequestorInfo requestor, final BigInteger crlNumber)
            throws OperationException {
        ParamUtil.requireNonNull("requestor", requestor);
        try {
            checkPermission(requestor, PermissionConstants.GET_CRL);
        } catch (InsuffientPermissionException ex) {
            throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
        }
        X509Ca ca = getCa();
        return (crlNumber == null) ? ca.getBcCurrentCrl() : ca.getBcCrl(crlNumber);
    }

    /**
     * @since 2.1.0
     */
    public X509CRL generateCrlOnDemand(final CmpRequestorInfo requestor,
            final RequestType reqType, final String msgId) throws OperationException {
        ParamUtil.requireNonNull("requestor", requestor);
        try {
            checkPermission(requestor, PermissionConstants.GEN_CRL);
        } catch (InsuffientPermissionException ex) {
            throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
        }

        X509Ca ca = getCa();
        return ca.generateCrlOnDemand(msgId);
    }

    /**
     * @since 2.1.0
     */
    public void revokeCert(final CmpRequestorInfo requestor, final BigInteger serialNumber,
            final CrlReason reason, final Date invalidityDate, final RequestType reqType,
            final String msgId) throws OperationException {
        ParamUtil.requireNonNull("requestor", requestor);

        int permission;
        if (reason == CrlReason.REMOVE_FROM_CRL) {
            permission = PermissionConstants.UNREVOKE_CERT;
        } else {
            permission = PermissionConstants.REVOKE_CERT;
        }
        try {
            checkPermission(requestor, permission);
        } catch (InsuffientPermissionException ex) {
            throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
        }

        X509Ca ca = getCa();
        Object returnedObj;
        if (PermissionConstants.UNREVOKE_CERT == permission) {
            // unrevoke
            returnedObj = ca.unrevokeCertificate(serialNumber, msgId);
        } else {
            returnedObj = ca.revokeCertificate(serialNumber, reason, invalidityDate, msgId);
        } // end if (permission)

        if (returnedObj == null) {
            throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
        }
    }

    /**
     * @since 2.1.0
     */
    public void removeCert(final CmpRequestorInfo requestor, final BigInteger serialNumber,
            final RequestType reqType, final String msgId)
            throws OperationException {
        ParamUtil.requireNonNull("requestor", requestor);
        try {
            checkPermission(requestor, PermissionConstants.REMOVE_CERT);
        } catch (InsuffientPermissionException ex) {
            throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
        }

        X509Ca ca = getCa();
        X509CertWithDbId returnedObj = ca.removeCertificate(serialNumber, msgId);
        if (returnedObj == null) {
            throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
        }
    }

    private static PKIBody buildErrorMsgPkiBody(final PKIStatus pkiStatus, final int failureInfo,
            final String statusMessage) {
        PKIFreeText pkiStatusMsg = (statusMessage == null) ? null : new PKIFreeText(statusMessage);
        ErrorMsgContent emc = new ErrorMsgContent(
                new PKIStatusInfo(pkiStatus, pkiStatusMsg, new PKIFailureInfo(failureInfo)));
        return new PKIBody(PKIBody.TYPE_ERROR, emc);
    }

    private CertResponse buildErrorCertResponse(ASN1Integer certReqId, int pkiFailureInfo,
            String msg) {
        return buildErrorCertResponse(certReqId, pkiFailureInfo, msg, msg);
    }

    private CertResponse buildErrorCertResponse(ASN1Integer certReqId, int pkiFailureInfo,
            String msg, String pkiStatusText) {
        return new CertResponse(certReqId, generateRejectionStatus(pkiFailureInfo, pkiStatusText));
    }

}
