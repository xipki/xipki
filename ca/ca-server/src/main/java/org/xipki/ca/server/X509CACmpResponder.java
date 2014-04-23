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

package org.xipki.ca.server;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
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
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.ChildAuditEvent;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.api.CertAlreadyIssuedException;
import org.xipki.ca.api.InsuffientPermissionException;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.profile.OriginalProfileConf;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.cmp.CmpUtil;
import org.xipki.ca.cmp.server.CmpControl;
import org.xipki.ca.cmp.server.CmpResponder;
import org.xipki.ca.common.RequestorInfo;
import org.xipki.ca.server.mgmt.Permission;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.CustomObjectIdentifiers;
import org.xipki.security.common.HealthCheckResult;
import org.xipki.security.common.IoCertUtil;

public class X509CACmpResponder extends CmpResponder
{
    private static final Logger LOG = LoggerFactory.getLogger(X509CACmpResponder.class);
    private static final CRLReason CRLReason_cessationOfOperation = CRLReason.lookup(CRLReason.cessationOfOperation);

    private final PendingCertificatePool pendingCertPool;

    private final X509CA ca;

    private static final String[] crlreasonString =
    {
        "unspecified", "keyCompromise", "cACompromise", "affiliationChanged",
        "superseded", "cessationOfOperation", "certificateHold", "unknown",
        "removeFromCRL", "privilegeWithdrawn", "aACompromise"
    };

    public X509CACmpResponder(X509CA ca, ConcurrentContentSigner responder, SecurityFactory securityFactory)
    {
        super(responder, securityFactory);

        this.ca = ca;
        this.pendingCertPool = new PendingCertificatePool();

        PendingPoolCleaner pendingPoolCleaner = new PendingPoolCleaner();
        ca.getCAManager().getScheduledThreadPoolExecutor().scheduleAtFixedRate(
            pendingPoolCleaner, 10, 10, TimeUnit.MINUTES);
    }

    public X509CA getCA()
    {
        return ca;
    }

    @Override
    public boolean isCAInService()
    {
        return CAStatus.ACTIVE == ca.getCAInfo().getStatus();
    }

    public HealthCheckResult healthCheck()
    {
        boolean healthy = true;

        HealthCheckResult result = ca.healthCheck();

        boolean responderHealthy = responder.isHealthy();
        healthy &= responderHealthy;

        result.setHealthy(healthy);
        result.putStatus("Responder.healthy", responderHealthy);
        return result;
    }

    @Override
    protected PKIMessage intern_processPKIMessage(RequestorInfo requestor, String user,
            ASN1OctetString tid, GeneralPKIMessage message, AuditEvent auditEvent)
    {
        if(requestor instanceof CmpRequestorInfo == false)
        {
            throw new IllegalArgumentException("Unknown requestor type " + requestor.getClass().getName());
        }

        CmpRequestorInfo _requestor = (CmpRequestorInfo) requestor;

        PKIHeader reqHeader = message.getHeader();
        PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
                reqHeader.getPvno().getValue().intValue(),
                sender,
                reqHeader.getSender());
        respHeader.setTransactionID(tid);

        PKIBody respBody;
        PKIBody reqBody = message.getBody();
        final int type = reqBody.getType();

        CmpControl cmpControl = getCmpControl();
        long confirmWaitTime = cmpControl.getConfirmWaitTime();
        if(confirmWaitTime < 0)
        {
            confirmWaitTime *= -1;
        }
        confirmWaitTime *= 1000; // second to millisecond

        String eventType = null;

        try
        {
            switch(type)
            {
                case PKIBody.TYPE_CERT_REQ:
                case PKIBody.TYPE_KEY_UPDATE_REQ:
                case PKIBody.TYPE_P10_CERT_REQ:
                case PKIBody.TYPE_CROSS_CERT_REQ:
                    boolean sendCaCert = cmpControl.isSendCaCert();
                    switch(type)
                    {
                        case PKIBody.TYPE_CERT_REQ:
                            eventType = "CERT_REQ";
                            checkPermission(_requestor, Permission.CERT_REQ);
                            respBody = processCr(_requestor, user, tid, reqHeader,
                                    (CertReqMessages) reqBody.getContent(), confirmWaitTime, sendCaCert, auditEvent);
                            break;
                        case PKIBody.TYPE_KEY_UPDATE_REQ:
                            eventType = "KEY_UPDATE";
                            checkPermission(_requestor, Permission.KEY_UPDATE);
                            respBody = processKur(_requestor, user, tid, reqHeader,
                                    (CertReqMessages) reqBody.getContent(), confirmWaitTime, sendCaCert, auditEvent);
                            break;
                        case PKIBody.TYPE_P10_CERT_REQ:
                            eventType = "CERT_REQ";
                            checkPermission(_requestor, Permission.CERT_REQ);
                            respBody = processP10cr(_requestor, user, tid, reqHeader,
                                    (CertificationRequest) reqBody.getContent(), confirmWaitTime, sendCaCert, auditEvent);
                            break;
                        default: // PKIBody.TYPE_CROSS_CERT_REQ
                            eventType = "CROSS_CERT_REQ";
                            checkPermission(_requestor, Permission.CROSS_CERT_REQ);
                            respBody = processCcp(_requestor, user, tid, reqHeader,
                                    (CertReqMessages) reqBody.getContent(), confirmWaitTime, sendCaCert, auditEvent);
                            break;
                    }

                    boolean successfull = false;

                    InfoTypeAndValue tv = null;

                    if(cmpControl.isRequireConfirmCert() == false && CmpUtil.isImplictConfirm(reqHeader))
                    {
                        successfull = publishPendingCertificates(tid);
                        if(successfull)
                        {
                            tv = CmpUtil.getImplictConfirmGeneralInfo();
                        }
                    }
                    else
                    {
                        Date now = new Date();
                        respHeader.setMessageTime(new ASN1GeneralizedTime(now));
                        tv = new InfoTypeAndValue(
                                CMPObjectIdentifiers.it_confirmWaitTime,
                                new ASN1GeneralizedTime(new Date(System.currentTimeMillis() + confirmWaitTime)));
                    }
                    if(tv != null)
                    {
                        respHeader.setGeneralInfo(tv);
                    }

                    if(successfull == false)
                    {
                        ErrorMsgContent emc = new ErrorMsgContent(
                                new PKIStatusInfo(PKIStatus.rejection,
                                        null,
                                        new PKIFailureInfo(PKIFailureInfo.systemFailure)));

                        respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
                    }

                    break;
                case PKIBody.TYPE_CERT_CONFIRM:
                {
                    eventType = "CERT_CONFIRM";
                    CertConfirmContent certConf = (CertConfirmContent) reqBody.getContent();
                    respBody = confirmCertificates(tid, certConf);
                    break;
                }
                case PKIBody.TYPE_REVOCATION_REQ:
                {
                    eventType = "CERT_REV";
                    checkPermission(_requestor, Permission.CERT_REV);
                    RevReqContent rr = (RevReqContent) reqBody.getContent();
                    respBody = revocateCertificates(rr, auditEvent);
                    break;
                }
                case PKIBody.TYPE_CONFIRM:
                {
                    eventType = "CONFIRM";
                    respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
                }
                case PKIBody.TYPE_ERROR:
                {
                    eventType = "ERROR";
                    revocatePendingCertificates(tid);
                    respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
                    break;
                }
                case PKIBody.TYPE_GEN_MSG:
                {
                    eventType = "GEN_MSG";
                    GenMsgContent genMsgBody = (GenMsgContent) reqBody.getContent();
                    InfoTypeAndValue[] itvs = genMsgBody.toInfoTypeAndValueArray();

                    InfoTypeAndValue itvCRL = null;
                    if(itvs != null && itvs.length > 0)
                    {
                        for(InfoTypeAndValue itv : itvs)
                        {
                            String itvType = itv.getInfoType().getId();
                            if(CMPObjectIdentifiers.it_currentCRL.getId().equals(itvType) ||
                                    CustomObjectIdentifiers.id_cmp_generateCRL.equals(itvType))
                            {
                                itvCRL = itv;
                                break;
                            }
                        }
                    }

                    respBody = null;

                    PKIStatus status = PKIStatus.rejection;
                    String statusMessage = null;
                    int failureInfo = PKIFailureInfo.badRequest;

                    if(itvCRL == null)
                    {
                        statusMessage = "PKIBody type " + type + " is only supported with the sub-types "
                                + CMPObjectIdentifiers.it_currentCRL.getId() + " and "
                                + CustomObjectIdentifiers.id_cmp_generateCRL;
                        failureInfo = PKIFailureInfo.badRequest;
                    }
                    else
                    {
                        ASN1ObjectIdentifier infoType = itvCRL.getInfoType();

                        CertificateList crl = null;
                        try
                        {
                            if(CMPObjectIdentifiers.it_currentCRL.equals(infoType))
                            {
                                eventType = "CRL_DOWNLOAD";
                                checkPermission(_requestor, Permission.CRL_DOWNLOAD);
                                crl = ca.getCurrentCRL();
                                if(crl == null)
                                {
                                    statusMessage = "No CRL is available";
                                    failureInfo = PKIFailureInfo.badRequest;
                                }
                            }
                            else
                            {
                                eventType = "CRL_GEN";
                                checkPermission(_requestor, Permission.CRL_GEN);
                                X509CRL _crl = ca.generateCRL();
                                if(_crl == null)
                                {
                                    statusMessage = "CRL generation is not activated";
                                    failureInfo = PKIFailureInfo.badRequest;
                                }
                                else
                                {
                                    crl = CertificateList.getInstance(_crl.getEncoded());
                                }
                            }

                            if(crl != null)
                            {
                                status = PKIStatus.granted;
                                InfoTypeAndValue itv = new InfoTypeAndValue(infoType, crl);
                                GenRepContent genRepContent = new GenRepContent(itv);
                                respBody = new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
                            }
                        } catch (OperationException e)
                        {
                            failureInfo = PKIFailureInfo.systemFailure;
                        } catch (CRLException e)
                        {
                            failureInfo = PKIFailureInfo.systemFailure;
                        }
                    }

                    if(respBody == null)
                    {
                        ErrorMsgContent emc = new ErrorMsgContent(
                            new PKIStatusInfo(status,
                                    (statusMessage == null) ? null : new PKIFreeText(statusMessage),
                                    new PKIFailureInfo(failureInfo)));
                        respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
                    }

                    break;
                }
                default:
                {
                    eventType = "PKIBody." + type;
                    ErrorMsgContent emc = new ErrorMsgContent(
                            new PKIStatusInfo(PKIStatus.rejection,
                                    new PKIFreeText("unsupported type " + type),
                                    new PKIFailureInfo(PKIFailureInfo.badRequest)));

                    respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
                    break;
                }
            }
        }catch(InsuffientPermissionException e)
        {
            ErrorMsgContent emc = new ErrorMsgContent(
                    new PKIStatusInfo(PKIStatus.rejection,
                            new PKIFreeText(e.getMessage()),
                            new PKIFailureInfo(PKIFailureInfo.notAuthorized)));

            respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
        }

        if(auditEvent != null)
        {
            if(eventType != null)
            {
                auditEvent.addEventData(new AuditEventData("eventType", eventType));
            }

            if(_requestor != null)
            {
                auditEvent.addEventData(new AuditEventData("requestor", _requestor.getCertificate().getSubject()));
            }

            if(user != null)
            {
                auditEvent.addEventData(new AuditEventData("user", user));
            }

            if(respBody.getType() == PKIBody.TYPE_ERROR)
            {
                ErrorMsgContent errorMsgContent = (ErrorMsgContent) respBody.getContent();
                int pkiErrorCode = errorMsgContent.getErrorCode().getPositiveValue().intValue();

                if(pkiErrorCode == PKIFailureInfo.systemFailure)
                {
                    auditEvent.setStatus(AuditStatus.error);
                }
                else
                {
                    auditEvent.setStatus(AuditStatus.failed);
                }

                String statusString = null;

                if(errorMsgContent.getPKIStatusInfo() != null)
                {
                    PKIFreeText pkiFreeText = errorMsgContent.getPKIStatusInfo().getStatusString();
                    if(pkiFreeText != null)
                    {
                        statusString = pkiFreeText.getStringAt(0).getString();
                    }
                }

                if(statusString != null)
                {
                    auditEvent.addEventData(new AuditEventData("message", statusString));
                }
            }
            else if(auditEvent.getStatus() == null)
            {
                auditEvent.setStatus(AuditStatus.successfull);
            }
        }

        return new PKIMessage(respHeader.build(), respBody);
    }

    /**
     * handle the PKI body with the choice {@code cr}
     *
     */
    private PKIBody processCr(CmpRequestorInfo requestor, String user, ASN1OctetString tid, PKIHeader reqHeader,
            CertReqMessages cr, long confirmWaitTime, boolean sendCaCert, AuditEvent auditEvent)
    throws InsuffientPermissionException
    {
        CertRepMessage repMessage = processCertReqMessages(requestor, user, tid, reqHeader, cr,
                false, confirmWaitTime, sendCaCert, auditEvent);
        return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
    }

    private PKIBody processKur(CmpRequestorInfo requestor, String user, ASN1OctetString tid, PKIHeader reqHeader,
            CertReqMessages kur, long confirmWaitTime, boolean sendCaCert, AuditEvent auditEvent)
    throws InsuffientPermissionException
    {
        CertRepMessage repMessage = processCertReqMessages(requestor, user, tid, reqHeader, kur,
                true, confirmWaitTime, sendCaCert, auditEvent);
        return new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, repMessage);
    }

    /**
     * handle the PKI body with the choice {@code cr}
     *
     */
    private PKIBody processCcp(CmpRequestorInfo requestor, String user,
            ASN1OctetString tid, PKIHeader reqHeader,
            CertReqMessages cr, long confirmWaitTime, boolean sendCaCert, AuditEvent auditEvent)
    throws InsuffientPermissionException
    {
        CertRepMessage repMessage = processCertReqMessages(requestor, user, tid, reqHeader, cr,
                false, confirmWaitTime, sendCaCert, auditEvent);
        return new PKIBody(PKIBody.TYPE_CROSS_CERT_REP, repMessage);
    }

    private CertRepMessage processCertReqMessages(
            CmpRequestorInfo requestor,
            String user,
            ASN1OctetString tid,
            PKIHeader reqHeader,
            CertReqMessages kur,
            boolean keyUpdate, long confirmWaitTime, boolean sendCaCert,
            AuditEvent auditEvent)
    throws InsuffientPermissionException
    {
        CmpRequestorInfo _requestor = (CmpRequestorInfo) requestor;

        CertReqMsg[] certReqMsgs = kur.toCertReqMsgArray();
        CertResponse[] certResponses = new CertResponse[certReqMsgs.length];

        for(int i=0; i<certReqMsgs.length; i++)
        {
            ChildAuditEvent childAuditEvent = null;
            if(auditEvent != null)
            {
                childAuditEvent = new ChildAuditEvent();
                auditEvent.addChildAuditEvent(childAuditEvent);
            }

            CertReqMsg reqMsg = certReqMsgs[i];
            CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);
            ASN1Integer certReqId = reqMsg.getCertReq().getCertReqId();
            if(childAuditEvent != null)
            {
                childAuditEvent.addEventData(new AuditEventData("CertReqId", certReqId.getPositiveValue().intValue()));
            }

            if(req.hasProofOfPossession() == false)
            {
                PKIStatusInfo status = generateCmpRejectionStatus(PKIFailureInfo.badPOP, null);
                certResponses[i] = new CertResponse(certReqId, status);

                if(childAuditEvent != null)
                {
                    childAuditEvent.setStatus(AuditStatus.failed);
                    childAuditEvent.addEventData(new AuditEventData("message", "no POP"));
                }
            }
            else
            {
                if(verifyPOP(req, _requestor.isRA()) == false)
                {
                    LOG.warn("could not validate POP for requst {}", certReqId.getValue());
                    PKIStatusInfo status = generateCmpRejectionStatus(PKIFailureInfo.badPOP, null);
                    certResponses[i] = new CertResponse(certReqId, status);
                    if(childAuditEvent != null)
                    {
                        childAuditEvent.setStatus(AuditStatus.failed);
                        childAuditEvent.addEventData(new AuditEventData("message", "invalid POP"));
                    }
                }
                else
                {
                    CertTemplate certTemp = req.getCertTemplate();
                    Extensions extensions = certTemp.getExtensions();
                    X500Name subject = certTemp.getSubject();
                    if(childAuditEvent != null)
                    {
                        childAuditEvent.addEventData(new AuditEventData("subject", IoCertUtil.canonicalizeName(subject)));
                    }
                    SubjectPublicKeyInfo publicKeyInfo = certTemp.getPublicKey();
                    OptionalValidity validity = certTemp.getValidity();

                    try
                    {
                        String certProfileName = getCertProfileName(reqMsg);
                        if(childAuditEvent != null)
                        {
                            childAuditEvent.addEventData(new AuditEventData("certprofile", certProfileName));
                        }

                        checkPermission(_requestor, certProfileName);
                        OriginalProfileConf originalProfileConf = getOrigCertProfileConf(reqMsg);
                        if(childAuditEvent != null && originalProfileConf != null)
                        {
                            childAuditEvent.addEventData(new AuditEventData("origCertprofile",
                                    originalProfileConf.getProfileName()));
                        }

                        certResponses[i] = generateCertificate(_requestor, user, tid, certReqId,
                                subject, publicKeyInfo,validity, extensions,
                                certProfileName, originalProfileConf,
                                keyUpdate, confirmWaitTime, childAuditEvent);
                    } catch (CMPException e)
                    {
                        LOG.warn("generateCertificate, CMPException: {}", e.getMessage());
                        LOG.debug("generateCertificate", e);

                        certResponses[i] = new CertResponse(certReqId,
                                generateCmpRejectionStatus(PKIFailureInfo.badCertTemplate, e.getMessage()));

                        if(childAuditEvent != null)
                        {
                            childAuditEvent.setStatus(AuditStatus.error);
                            childAuditEvent.addEventData(new AuditEventData("message", "badCertTemplate"));
                        }
                    } catch (ParseException e)
                    {
                        LOG.warn("generateCertificate, ParseException: {}", e.getMessage());
                        LOG.debug("generateCertificate", e);
                        certResponses[i] = new CertResponse(certReqId,
                                generateCmpRejectionStatus(PKIFailureInfo.badCertTemplate, e.getMessage()));
                        if(childAuditEvent != null)
                        {
                            childAuditEvent.setStatus(AuditStatus.error);
                            childAuditEvent.addEventData(new AuditEventData("message", "badCertTemplate"));
                        }
                    }
                }
            }
        }

        CMPCertificate[] caPubs = sendCaCert ?
                new CMPCertificate[]{ca.getCAInfo().getCertInCMPFormat()} : null;
        return new CertRepMessage(caPubs, certResponses);
    }

    private static String getCertProfileName(PKIHeader pkiHeader)
    throws CMPException
    {
        InfoTypeAndValue[] regInfos = pkiHeader.getGeneralInfo();
        if(regInfos != null)
        {
            for (InfoTypeAndValue regInfo : regInfos)
            {
                if(CMPObjectIdentifiers.regInfo_utf8Pairs.equals(regInfo.getInfoType()))
                {
                    String regInfoValue = ((DERUTF8String) regInfo.getInfoValue()).getString();
                    CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(regInfoValue);
                    String certProfile = utf8Pairs.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);
                    if(certProfile != null)
                    {
                        return certProfile;
                    }
                }
            }
        }

        return null;
    }

    private static String getCertProfileName(CertReqMsg reqMsg)
    throws CMPException
    {
        AttributeTypeAndValue[] regInfos = reqMsg.getRegInfo();
        if(regInfos != null)
        {
            for (AttributeTypeAndValue regInfo : regInfos)
            {
                if(CMPObjectIdentifiers.regInfo_utf8Pairs.equals(regInfo.getType()))
                {
                    String regInfoValue = ((DERUTF8String) regInfo.getValue()).getString();
                    CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(regInfoValue);
                    String certProfile = utf8Pairs.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);
                    if(certProfile != null)
                    {
                        return certProfile;
                    }
                }
            }
        }

        return null;
    }

    private static OriginalProfileConf getOrigCertProfileConf(CertReqMsg reqMsg)
    throws CMPException, ParseException
    {
        String origCertProfileConf = null;
        AttributeTypeAndValue[] regInfos = reqMsg.getRegInfo();
        if(regInfos != null)
        {
            for (AttributeTypeAndValue regInfo : regInfos)
            {
                if(CMPObjectIdentifiers.regInfo_utf8Pairs.equals(regInfo.getType()))
                {
                    String regInfoValue = ((DERUTF8String) regInfo.getValue()).getString();
                    CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(regInfoValue);
                    String certProfile = utf8Pairs.getValue(CmpUtf8Pairs.KEY_ORIG_CERT_PROFILE);
                    if(certProfile != null)
                    {
                        origCertProfileConf = certProfile;
                        break;
                    }
                }
            }
        }

        if(origCertProfileConf == null || origCertProfileConf.isEmpty())
        {
            return null;
        }

        OriginalProfileConf origCertProfile = OriginalProfileConf.getInstance(origCertProfileConf);
        return origCertProfile;
    }

    /**
     * handle the PKI body with the choice {@code p10cr}<br/>
     * Since it is not possible to add attribute to the PKCS#10 request, the certificate profile
     * must be specified in the attribute regInfo-utf8Pairs (1.3.6.1.5.5.7.5.2.1) within
     * PKIHeader.generalInfo
     *
     */
    private PKIBody processP10cr(CmpRequestorInfo requestor, String user, ASN1OctetString tid, PKIHeader reqHeader,
            CertificationRequest p10cr, long confirmWaitTime, boolean sendCaCert, AuditEvent auditEvent)
    throws InsuffientPermissionException
    {
        // verify the POP first
        CertResponse certResp;
        ASN1Integer certReqId = new ASN1Integer(-1);

        ChildAuditEvent childAuditEvent = null;
        if(auditEvent != null)
        {
            childAuditEvent = new ChildAuditEvent();
            auditEvent.addChildAuditEvent(childAuditEvent);
        }

        if(securityFactory.verifyPOPO(p10cr) == false)
        {
            LOG.warn("could not validate POP for the pkcs#10 requst");
            PKIStatusInfo status = generateCmpRejectionStatus(PKIFailureInfo.badPOP, null);
            certResp = new CertResponse(certReqId, status);
            if(childAuditEvent != null)
            {
                childAuditEvent.setStatus(AuditStatus.failed);
                childAuditEvent.addEventData(new AuditEventData("message", "invalid POP"));
            }
        }
        else
        {
            CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
            Extensions extensions = null;
            ASN1Set attrs = certTemp.getAttributes();
            for(int i=0; i<attrs.size(); i++)
            {
                Attribute attr = (Attribute) attrs.getObjectAt(i);
                if(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType()))
                {
                    extensions = (Extensions) attr.getAttributeValues()[0];
                }
            }

            X500Name subject = certTemp.getSubject();
            if(childAuditEvent != null)
            {
                childAuditEvent.addEventData(new AuditEventData("subject", IoCertUtil.canonicalizeName(subject)));
            }

            SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

            try
            {
                String certProfileName = getCertProfileName(reqHeader);
                if(childAuditEvent != null)
                {
                    childAuditEvent.addEventData(new AuditEventData("certprofile", certProfileName));
                }
                checkPermission(requestor, certProfileName);

                certResp = generateCertificate(requestor, user, tid, certReqId,
                    subject, publicKeyInfo, null, extensions, certProfileName, null,
                    false, confirmWaitTime, childAuditEvent);
            }catch(CMPException e)
            {
                certResp = new CertResponse(certReqId, generateCmpRejectionStatus(PKIFailureInfo.badCertTemplate,
                        e.getMessage()));
                if(childAuditEvent != null)
                {
                    childAuditEvent.setStatus(AuditStatus.error);
                    childAuditEvent.addEventData(new AuditEventData("message", "badCertTemplate"));
                }
            }
        }

        CMPCertificate[] caPubs = sendCaCert ?
                new CMPCertificate[]{ca.getCAInfo().getCertInCMPFormat()} : null;
        CertRepMessage repMessage = new CertRepMessage(caPubs, new CertResponse[]{certResp});

        return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
    }

    private CertResponse generateCertificate(
            CmpRequestorInfo requestor,
            String user,
            ASN1OctetString tid,
            ASN1Integer certReqId,
            X500Name subject,
            SubjectPublicKeyInfo publicKeyInfo,
            OptionalValidity validity,
            Extensions extensions,
            String certProfileName,
            OriginalProfileConf origCertProfile,
            boolean keyUpdate,
            long confirmWaitTime,
            ChildAuditEvent childAuditEvent)
    throws InsuffientPermissionException
    {
        checkPermission(requestor, certProfileName);

        Date notBefore = null;
        Date notAfter = null;
        if(validity != null)
        {
            Time t = validity.getNotBefore();
            if(t != null)
            {
                notBefore = t.getDate();
            }
            t = validity.getNotAfter();
            if(t != null)
            {
                notAfter = t.getDate();
            }
        }

        try
        {
            CertificateInfo certInfo;
            if(keyUpdate)
            {
                certInfo = ca.regenerateCertificate(requestor.isRA(), certProfileName, origCertProfile,
                        subject, publicKeyInfo,
                        notBefore, notAfter, extensions);
            }
            else
            {
                certInfo = ca.generateCertificate(requestor.isRA(), certProfileName, origCertProfile,
                        subject, publicKeyInfo,
                        notBefore, notAfter, extensions);
            }
            certInfo.setRequestor(requestor);
            certInfo.setUser(user);

            pendingCertPool.addCertificate(tid.getOctets(), certReqId.getPositiveValue(),
                    certInfo, System.currentTimeMillis() + confirmWaitTime);
            String warningMsg = certInfo.getWarningMessage();

            PKIStatusInfo statusInfo;
            if(warningMsg == null || warningMsg.isEmpty())
            {
                statusInfo = new PKIStatusInfo(PKIStatus.granted);
            }
            else
            {
                statusInfo = new PKIStatusInfo(PKIStatus.grantedWithMods, new PKIFreeText(warningMsg));
            }

            if(childAuditEvent != null)
            {
                childAuditEvent.setStatus(AuditStatus.successfull);
            }

            CertOrEncCert cec = new CertOrEncCert(
                    CMPCertificate.getInstance(
                            certInfo.getCert().getEncodedCert()));
            CertifiedKeyPair kp = new CertifiedKeyPair(cec);
            CertResponse certResp = new CertResponse(certReqId, statusInfo, kp, null);
            return certResp;
        }catch (CertAlreadyIssuedException e)
        {
            LOG.warn("geneate certificate, CertAlreadyIssuedException: {}", e.getMessage());
            int failureInfo = PKIFailureInfo.incorrectData;
            PKIStatusInfo status = generateCmpRejectionStatus(failureInfo, e.getMessage());
            if(childAuditEvent != null)
            {
                childAuditEvent.setStatus(AuditStatus.failed);
                childAuditEvent.addEventData(new AuditEventData("message", "cert already issued"));
            }
            return new CertResponse(certReqId, status);
        }catch(OperationException ce)
        {
            LOG.warn("geneate certificate, OperationException: {}", ce.getMessage());

            AuditStatus auditStatus;
            String auditMessage;
            int failureInfo;
            switch(ce.getErrorCode())
            {
                case CERT_REVOKED:
                    failureInfo = PKIFailureInfo.certRevoked;
                    auditStatus = AuditStatus.failed;
                    auditMessage = "CERT_REVOKED";
                    break;
                case UNKNOWN_CERT:
                    failureInfo = PKIFailureInfo.badCertId;
                    auditStatus = AuditStatus.failed;
                    auditMessage = "UNKNOWN_CERT";
                    break;
                case UNKNOWN_CERT_PROFILE:
                    failureInfo = PKIFailureInfo.badCertTemplate;
                    auditStatus = AuditStatus.failed;
                    auditMessage = "UNKNOWN_CERT_PROFILE";
                    break;
                case EMPTY_SUBJECT:
                    failureInfo = PKIFailureInfo.badCertTemplate;
                    auditStatus = AuditStatus.failed;
                    auditMessage = "EMPTY_SUBJECT";
                    break;
                case BAD_CERT_TEMPLATE:
                    failureInfo = PKIFailureInfo.badCertTemplate;
                    auditStatus = AuditStatus.failed;
                    auditMessage = "BAD_CERT_TEMPLATE";
                    break;
                case System_Failure:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditStatus = AuditStatus.error;
                    auditMessage = "System_Failure";
                    break;
                default:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditStatus = AuditStatus.error;
                    auditMessage = "InternalErrorCode " + ce.getErrorCode();
                    break;
            }

               childAuditEvent.setStatus(auditStatus);
               childAuditEvent.addEventData(new AuditEventData("message", auditMessage));
            PKIStatusInfo status = generateCmpRejectionStatus(failureInfo, ce.getErrorMessage());
            return new CertResponse(certReqId, status);
        }
    }

    private PKIBody revocateCertificates(RevReqContent rr, AuditEvent auditEvent)
    {
        RevDetails[] revContent = rr.toRevDetailsArray();

        RevRepContentBuilder repContentBuilder = new RevRepContentBuilder();

        int n = revContent.length;
        for (int i = 0; i < n; i++)
        {
            ChildAuditEvent childAuditEvent = null;
            if(auditEvent != null)
            {
                childAuditEvent = new ChildAuditEvent();
                auditEvent.addChildAuditEvent(childAuditEvent);
            }

            RevDetails revDetails = revContent[i];

            CertTemplate certDetails = revDetails.getCertDetails();
            ASN1Integer serialNumber = certDetails.getSerialNumber();
            if(childAuditEvent != null)
            {
                childAuditEvent.addEventData(new AuditEventData("serialNumber", serialNumber.getPositiveValue()));
            }

            Extensions crlDetails = revDetails.getCrlEntryDetails();

            ASN1ObjectIdentifier extId = X509Extension.reasonCode;
            ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
            int reasonCode = ((ASN1Enumerated) extValue).getValue().intValue();
            CRLReason reason = CRLReason.lookup(reasonCode);
            if(childAuditEvent != null)
            {
                childAuditEvent.addEventData(new AuditEventData("reason",
                        reason == null ? Integer.toString(reasonCode) : crlreasonString[reasonCode]));
            }

            Date invalidityDate = null;

            extId = X509Extension.invalidityDate;
            extValue = crlDetails.getExtensionParsedValue(extId);
            if(extValue != null)
            {
                try
                {
                    invalidityDate = ((ASN1GeneralizedTime) extValue).getDate();
                } catch (ParseException e)
                {
                    String errMsg = "invalid extension " + extId.getId();
                    LOG.warn(errMsg);
                    PKIStatusInfo status = generateCmpRejectionStatus(PKIFailureInfo.unacceptedExtension, errMsg);
                    repContentBuilder.add(status);
                    continue;
                }

                if(childAuditEvent != null)
                {
                    childAuditEvent.addEventData(new AuditEventData("invalidityDate", invalidityDate));
                }
            }

            try
            {
                X509Certificate revokedCert = ca.revocateCertificate(
                        serialNumber.getPositiveValue(), reason, invalidityDate);

                if(revokedCert != null)
                {
                    PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
                    CertId certId = new CertId(new GeneralName(ca.getCASubjectX500Name()), serialNumber);
                    repContentBuilder.add(status, certId);
                    if(childAuditEvent != null)
                    {
                        childAuditEvent.setStatus(AuditStatus.successfull);
                    }
                }
                else
                {
                    PKIStatusInfo status = new PKIStatusInfo(
                            PKIStatus.rejection, new PKIFreeText("The given certificate does not exist,"),
                            new PKIFailureInfo(PKIFailureInfo.incorrectData));
                    repContentBuilder.add(status);
                    if(childAuditEvent != null)
                    {
                        childAuditEvent.setStatus(AuditStatus.failed);
                        childAuditEvent.addEventData(new AuditEventData("message", "cert not exists"));
                    }
                }
            } catch(OperationException e)
            {
                PKIStatusInfo status = new PKIStatusInfo(
                        PKIStatus.rejection, null, new PKIFailureInfo(PKIFailureInfo.systemFailure));
                repContentBuilder.add(status);
                if(childAuditEvent != null)
                {
                    childAuditEvent.setStatus(AuditStatus.error);
                    childAuditEvent.addEventData(new AuditEventData("message", "internal error"));
                }
            }
        }

        return new PKIBody(PKIBody.TYPE_REVOCATION_REP, repContentBuilder.build());
    }

    private PKIBody confirmCertificates(
            ASN1OctetString transactionId,
            CertConfirmContent certConf)
    {
        CertStatus[] certStatuses = certConf.toCertStatusArray();

        boolean successfull = true;
        for(CertStatus certStatus : certStatuses)
        {
            ASN1Integer certReqId = certStatus.getCertReqId();
            byte[] certHash = certStatus.getCertHash().getOctets();
            CertificateInfo certInfo = pendingCertPool.removeCertificate(
                    transactionId.getOctets(), certReqId.getPositiveValue(), certHash);
            if(certInfo == null)
            {
                LOG.warn("no cert under transactionId={}, certReqId={} and certHash={}",
                        new Object[]{transactionId, certReqId, certStatus.getCertHash()});
                continue;
            }

            PKIStatusInfo statusInfo = certStatus.getStatusInfo();
            boolean accept = true;
            if(statusInfo != null)
            {
                int status = statusInfo.getStatus().intValue();
                if(PKIStatus.GRANTED != status && PKIStatus.GRANTED_WITH_MODS != status)
                {
                    accept = false;
                }
            }

            if(accept)
            {
                if(ca.publishCertificate(certInfo) == false)
                {
                    successfull = false;
                }
            }
            else
            {
                BigInteger serialNumber = certInfo.getCert().getCert().getSerialNumber();
                try
                {
                    ca.revocateCertificate(
                            serialNumber,
                            CRLReason_cessationOfOperation, new Date());
                } catch (OperationException e)
                {
                    LOG.warn("Could not revocated certificate ca={}, serialNumber={}", ca.getCAInfo().getName(), serialNumber);
                }

                successfull = false;
            }
        }

        // all other certificates should be revocated
        if(revocatePendingCertificates(transactionId))
        {
            successfull = false;
        }

        if(successfull)
        {
            return new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
        }
        else
        {
            ErrorMsgContent emc = new ErrorMsgContent(
                    new PKIStatusInfo(PKIStatus.rejection,
                            null,
                            new PKIFailureInfo(PKIFailureInfo.systemFailure)));

            return new PKIBody(PKIBody.TYPE_ERROR, emc);
        }
    }

    private boolean publishPendingCertificates(ASN1OctetString transactionId)
    {
        Set<CertificateInfo> remainingCerts = pendingCertPool.removeCertificates(
                transactionId.getOctets());

        boolean successfull = true;
        if(remainingCerts != null && remainingCerts.isEmpty() == false)
        {
            for(CertificateInfo remainingCert : remainingCerts)
            {
                if(ca.publishCertificate(remainingCert) == false)
                {
                    successfull = false;
                }
            }
        }

        return successfull;
    }

    private boolean revocatePendingCertificates(ASN1OctetString transactionId)
    {
        Set<CertificateInfo> remainingCerts = pendingCertPool.removeCertificates(transactionId.getOctets());

        boolean successfull = true;
        if(remainingCerts != null && remainingCerts.isEmpty() == false)
        {
            Date invalidityDate = new Date();
            for(CertificateInfo remainingCert : remainingCerts)
            {
                try
                {
                    ca.revocateCertificate(
                        remainingCert.getCert().getCert().getSerialNumber(),
                        CRLReason_cessationOfOperation, invalidityDate);
                }catch(OperationException e)
                {
                    successfull = false;
                }
            }
        }

        return successfull;
    }

    private boolean verifyPOP(CertificateRequestMessage certRequest, boolean allowRAPopo)
    {
        int popType = certRequest.getProofOfPossessionType();
        if(popType == CertificateRequestMessage.popRaVerified && allowRAPopo)
        {
            return true;
        }

        if(popType != CertificateRequestMessage.popSigningKey)
        {
            LOG.error("Unsupported POP type: " + popType);
            return false;
        }

        try
        {
            PublicKey publicKey = securityFactory.generatePublicKey(certRequest.getCertTemplate().getPublicKey());
            ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(publicKey);
            return certRequest.isValidSigningKeyPOP(cvp);
        } catch (InvalidKeyException e)
        {
            LOG.error("verifyPOP, InvalidKeyException: {}" , e.getMessage());
            LOG.debug("verifyPOP" , e);
        } catch (IllegalStateException e)
        {
            LOG.error("verifyPOP, IllegalStateException: {}" , e.getMessage());
            LOG.debug("verifyPOP" , e);
        } catch (CRMFException e)
        {
            LOG.error("verifyPOP, CRMFException: {}" , e.getMessage());
            LOG.debug("verifyPOP" , e);
        }
        return false;
    }

    @Override
    protected CmpControl getCmpControl()
    {
        return ca.getCAManager().getCmpControl();
    }

    private class PendingPoolCleaner implements Runnable
    {

        @Override
        public void run()
        {
            Set<CertificateInfo> remainingCerts = pendingCertPool.removeConfirmTimeoutedCertificates();

            if(remainingCerts != null && remainingCerts.isEmpty() == false)
            {
                Date invalidityDate = new Date();
                for(CertificateInfo remainingCert : remainingCerts)
                {
                    try
                    {
                        ca.revocateCertificate(
                            remainingCert.getCert().getCert().getSerialNumber(),
                            CRLReason_cessationOfOperation, invalidityDate);
                    }catch(Throwable t)
                    {
                    }
                }
            }
        }
    }

    private void checkPermission(CmpRequestorInfo requestor, String certProfile)
    throws InsuffientPermissionException
    {
        Set<String> profiles = requestor.getProfiles();
        if(profiles != null)
        {
            if(profiles.contains("all") || profiles.contains(certProfile))
            {
                return;
            }
        }

        String msg = "CertProfile " + certProfile + " is not allowed";
        LOG.warn(msg);
        throw new InsuffientPermissionException(msg);
    }

    private void checkPermission(CmpRequestorInfo requestor, Permission requiredPermission)
    throws InsuffientPermissionException
    {
        Set<Permission> permissions = ca.getCAInfo().getPermissions();
        boolean granted = false;
        if(permissions.contains(Permission.ALL) || permissions.contains(requiredPermission))
        {
            Set<Permission> rPermissions = requestor.getPermissions();
            if(rPermissions.contains(Permission.ALL) || rPermissions.contains(requiredPermission))
            {
                granted = true;
            }
        }

        if(granted == false)
        {
            String msg = requiredPermission.getPermission() + " is not allowed";
            LOG.warn(msg);
            throw new InsuffientPermissionException(msg);
        }
    }

}
