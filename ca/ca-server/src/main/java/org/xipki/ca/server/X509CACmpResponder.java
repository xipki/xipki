/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
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
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
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
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.ChildAuditEvent;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.api.InsuffientPermissionException;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.cmp.CmpUtil;
import org.xipki.ca.cmp.server.CmpControl;
import org.xipki.ca.cmp.server.CmpResponder;
import org.xipki.ca.common.RequestorInfo;
import org.xipki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.CustomObjectIdentifiers;
import org.xipki.security.common.HealthCheckResult;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.LogUtil;

/**
 * @author Lijun Liao
 */

public class X509CACmpResponder extends CmpResponder
{
    public static final int XiPKI_CRL_REASON_UNREVOKE = 100;
    public static final int XiPKI_CRL_REASON_REMOVE = 101;

    private static final Logger LOG = LoggerFactory.getLogger(X509CACmpResponder.class);

    private final PendingCertificatePool pendingCertPool;

    private final X509CA ca;
    private CmpControlEntry cmpControlEntry;
    private CmpControl cmpControl;

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
        HealthCheckResult result = ca.healthCheck();
        boolean healthy = result.isHealthy();

        boolean responderHealthy = responder.isHealthy();
        healthy &= responderHealthy;

        HealthCheckResult responderHealth = new HealthCheckResult("Responder");
        responderHealth.setHealthy(responderHealthy);
        result.addChildCheck(responderHealth);

        result.setHealthy(healthy);
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
                            checkPermission(_requestor, Permission.ENROLL_CERT);
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
                            checkPermission(_requestor, Permission.ENROLL_CERT);
                            respBody = processP10cr(_requestor, user, tid, reqHeader,
                                    (CertificationRequest) reqBody.getContent(), confirmWaitTime, sendCaCert, auditEvent);
                            break;
                        //case PKIBody.TYPE_CROSS_CERT_REQ:
                        default:
                            eventType = "CROSS_CERT_REQ";
                            checkPermission(_requestor, Permission.CROSS_CERT_ENROLL);
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
                    Permission requiredPermission = null;
                    boolean allRevdetailsOfSameType = true;

                    RevReqContent rr = (RevReqContent) reqBody.getContent();
                    RevDetails[] revContent = rr.toRevDetailsArray();

                    int n = revContent.length;
                    for (int i = 0; i < n; i++)
                    {
                        RevDetails revDetails = revContent[i];
                        Extensions crlDetails = revDetails.getCrlEntryDetails();
                        ASN1ObjectIdentifier extId = Extension.reasonCode;
                        ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
                        int reasonCode = ((ASN1Enumerated) extValue).getValue().intValue();
                        if(reasonCode == XiPKI_CRL_REASON_REMOVE)
                        {
                            if(requiredPermission == null)
                            {
                                eventType = "CERT_REMOVE";
                                requiredPermission = Permission.REMOVE_CERT;
                            }
                            else if(requiredPermission != Permission.REMOVE_CERT)
                            {
                                allRevdetailsOfSameType = false;
                                break;
                            }
                        }
                        else if(reasonCode == XiPKI_CRL_REASON_UNREVOKE)
                        {
                            if(requiredPermission == null)
                            {
                                eventType = "CERT_UNREVOKE";
                                requiredPermission = Permission.UNREVOKE_CERT;
                            }
                            else if(requiredPermission != Permission.UNREVOKE_CERT)
                            {
                                allRevdetailsOfSameType = false;
                                break;
                            }
                        }
                        else
                        {
                            if(requiredPermission == null)
                            {
                                eventType = "CERT_REVOKE";
                                requiredPermission = Permission.REVOKE_CERT;
                            }
                            else if(requiredPermission != Permission.REVOKE_CERT)
                            {
                                allRevdetailsOfSameType = false;
                                break;
                            }
                        }
                    }

                    if(allRevdetailsOfSameType == false)
                    {
                        ErrorMsgContent emc = new ErrorMsgContent(
                                new PKIStatusInfo(PKIStatus.rejection,
                                        new PKIFreeText("Not all revDetails are of the same type"),
                                        new PKIFailureInfo(PKIFailureInfo.badRequest)));

                        respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
                    }
                    else
                    {
                        checkPermission(_requestor, requiredPermission);
                        respBody = revokeOrUnrevokeOrRemoveCertificates(rr, auditEvent, requiredPermission);
                    }

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
                    revokePendingCertificates(tid);
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
                                checkPermission(_requestor, Permission.GET_CRL);
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
                                checkPermission(_requestor, Permission.GEN_CRL);
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

            if(respBody.getType() == PKIBody.TYPE_ERROR)
            {
                ErrorMsgContent errorMsgContent = (ErrorMsgContent) respBody.getContent();

                AuditStatus auditStatus = AuditStatus.FAILED;
                if(errorMsgContent.getErrorCode() != null)
                {
                    int pkiErrorCode = errorMsgContent.getErrorCode().getPositiveValue().intValue();

                    if(pkiErrorCode == PKIFailureInfo.systemFailure)
                    {
                        auditStatus = AuditStatus.ERROR;
                    }
                }
                auditEvent.setStatus(auditStatus);

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
                auditEvent.setStatus(AuditStatus.SUCCESSFUL);
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

        for(int i = 0; i < certReqMsgs.length; i++)
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
                childAuditEvent.addEventData(new AuditEventData("certReqId", certReqId.getPositiveValue().intValue()));
            }

            if(req.hasProofOfPossession() == false)
            {
                PKIStatusInfo status = generateCmpRejectionStatus(PKIFailureInfo.badPOP, null);
                certResponses[i] = new CertResponse(certReqId, status);

                if(childAuditEvent != null)
                {
                    childAuditEvent.setStatus(AuditStatus.FAILED);
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
                        childAuditEvent.setStatus(AuditStatus.FAILED);
                        childAuditEvent.addEventData(new AuditEventData("message", "invalid POP"));
                    }
                }
                else
                {
                    CertTemplate certTemp = req.getCertTemplate();
                    Extensions extensions = certTemp.getExtensions();
                    X500Name subject = certTemp.getSubject();
                    SubjectPublicKeyInfo publicKeyInfo = certTemp.getPublicKey();
                    OptionalValidity validity = certTemp.getValidity();

                    try
                    {
                        CmpUtf8Pairs keyvalues  = CmpUtil.extract(reqMsg.getRegInfo());
                        String certProfileName = keyvalues == null ? null : keyvalues.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);
                        if(certProfileName == null)
                        {
                            throw new CMPException("no certificate profile is specified");
                        }

                        if(childAuditEvent != null)
                        {
                            childAuditEvent.addEventData(new AuditEventData("certProfile", certProfileName));
                        }

                        checkPermission(_requestor, certProfileName);
                        certResponses[i] = generateCertificate(_requestor, user, tid, certReqId,
                                subject, publicKeyInfo,validity, extensions,
                                certProfileName, keyUpdate, confirmWaitTime, childAuditEvent);
                    } catch (CMPException e)
                    {
                        final String message = "generateCertificate";
                        if(LOG.isWarnEnabled())
                        {
                            LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                        }
                        LOG.debug(message, e);

                        certResponses[i] = new CertResponse(certReqId,
                                generateCmpRejectionStatus(PKIFailureInfo.badCertTemplate, e.getMessage()));

                        if(childAuditEvent != null)
                        {
                            childAuditEvent.setStatus(AuditStatus.ERROR);
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
                childAuditEvent.setStatus(AuditStatus.FAILED);
                childAuditEvent.addEventData(new AuditEventData("message", "invalid POP"));
            }
        }
        else
        {
            CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
            Extensions extensions = null;
            ASN1Set attrs = certTemp.getAttributes();
            for(int i = 0; i < attrs.size(); i++)
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
                CmpUtf8Pairs keyvalues = CmpUtil.extract(reqHeader.getGeneralInfo());
                String certProfileName = keyvalues == null ? null : keyvalues.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);
                if(certProfileName == null)
                {
                    throw new CMPException("no certificate profile is specified");
                }

                if(childAuditEvent != null)
                {
                    childAuditEvent.addEventData(new AuditEventData("certProfile", certProfileName));
                }

                checkPermission(requestor, certProfileName);

                certResp = generateCertificate(requestor, user, tid, certReqId,
                    subject, publicKeyInfo, null, extensions, certProfileName,
                    false, confirmWaitTime, childAuditEvent);
            }catch(CMPException e)
            {
                certResp = new CertResponse(certReqId, generateCmpRejectionStatus(PKIFailureInfo.badCertTemplate,
                        e.getMessage()));
                if(childAuditEvent != null)
                {
                    childAuditEvent.setStatus(AuditStatus.ERROR);
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
                certInfo = ca.regenerateCertificate(requestor.isRA(), certProfileName, user,
                        subject, publicKeyInfo,
                        notBefore, notAfter, extensions);
            }
            else
            {
                certInfo = ca.generateCertificate(requestor.isRA(), certProfileName, user,
                        subject, publicKeyInfo,
                        notBefore, notAfter, extensions);
            }
            certInfo.setRequestor(requestor);
            certInfo.setUser(user);

            if(childAuditEvent != null)
            {
                childAuditEvent.addEventData(new AuditEventData("subject",
                        certInfo.getCert().getSubject()));
            }

            pendingCertPool.addCertificate(tid.getOctets(), certReqId.getPositiveValue(),
                    certInfo, System.currentTimeMillis() + confirmWaitTime);
            String warningMsg = certInfo.getWarningMessage();

            PKIStatusInfo statusInfo;
            if(warningMsg == null || warningMsg.isEmpty())
            {
                if(certInfo.isAlreadyIssued())
                {
                    statusInfo = new PKIStatusInfo(PKIStatus.grantedWithMods, new PKIFreeText("ALREADY_ISSUED"));
                }
                else
                {
                    statusInfo = new PKIStatusInfo(PKIStatus.granted);
                }
            }
            else
            {
                statusInfo = new PKIStatusInfo(PKIStatus.grantedWithMods, new PKIFreeText(warningMsg));
            }

            if(childAuditEvent != null)
            {
                childAuditEvent.setStatus(AuditStatus.SUCCESSFUL);
            }

            CertOrEncCert cec = new CertOrEncCert(
                    CMPCertificate.getInstance(
                            certInfo.getCert().getEncodedCert()));
            CertifiedKeyPair kp = new CertifiedKeyPair(cec);
            CertResponse certResp = new CertResponse(certReqId, statusInfo, kp, null);
            return certResp;
        }catch(OperationException ce)
        {
            ErrorCode code = ce.getErrorCode();
            LOG.warn("generate certificate, OperationException: code={}, message={}",
                    code.name(), ce.getErrorMessage());

            AuditStatus auditStatus;
            String auditMessage;

            int failureInfo;
            switch(code)
            {
                case ALREADY_ISSUED:
                    failureInfo = PKIFailureInfo.badRequest;
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "ALREADY_ISSUED";
                    break;
                case BAD_CERT_TEMPLATE:
                    failureInfo = PKIFailureInfo.badCertTemplate;
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "BAD_CERT_TEMPLATE";
                    break;
                case CERT_REVOKED:
                    failureInfo = PKIFailureInfo.certRevoked;
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "CERT_REVOKED";
                    break;
                case CRL_FAILURE:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditStatus = AuditStatus.ERROR;
                    auditMessage = "CRL_FAILURE";
                    break;
                case DATABASE_FAILURE:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditStatus = AuditStatus.ERROR;
                    auditMessage = "DATABASE_FAILURE";
                    break;
                case NOT_PERMITTED:
                    failureInfo = PKIFailureInfo.notAuthorized;
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "NOT_PERMITTED";
                    break;
                case INSUFFICIENT_PERMISSION:
                    failureInfo = PKIFailureInfo.notAuthorized;
                    auditStatus = AuditStatus.ERROR;
                    auditMessage = "INSUFFICIENT_PERMISSION";
                    break;
                case INVALID_EXTENSION:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditStatus = AuditStatus.ERROR;
                    auditMessage = "INVALID_EXTENSION";
                    break;
                case System_Failure:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditStatus = AuditStatus.ERROR;
                    auditMessage = "System_Failure";
                    break;
                case UNKNOWN_CERT:
                    failureInfo = PKIFailureInfo.badCertId;
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "UNKNOWN_CERT";
                    break;
                case UNKNOWN_CERT_PROFILE:
                    failureInfo = PKIFailureInfo.badCertTemplate;
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "UNKNOWN_CERT_PROFILE";
                    break;
                default:
                    failureInfo = PKIFailureInfo.systemFailure;
                    auditStatus = AuditStatus.ERROR;
                    auditMessage = "InternalErrorCode " + ce.getErrorCode();
                    break;
            }

            if(childAuditEvent != null)
            {
                childAuditEvent.setStatus(auditStatus);
                childAuditEvent.addEventData(new AuditEventData("message", auditMessage));
            }

            String errorMessage = auditMessage;
            PKIStatusInfo status = generateCmpRejectionStatus(failureInfo, errorMessage);
            return new CertResponse(certReqId, status);
        }
    }

    private PKIBody revokeOrUnrevokeOrRemoveCertificates(RevReqContent rr, AuditEvent auditEvent, Permission permission)
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

            CRLReason reason = null;
            Date invalidityDate = null;

            if(Permission.REVOKE_CERT == permission)
            {
                Extensions crlDetails = revDetails.getCrlEntryDetails();

                ASN1ObjectIdentifier extId = Extension.reasonCode;
                ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
                int reasonCode = ((ASN1Enumerated) extValue).getValue().intValue();
                reason = CRLReason.forReasonCode(reasonCode);
                if(childAuditEvent != null)
                {
                    childAuditEvent.addEventData(new AuditEventData("reason",
                            reason == null ? Integer.toString(reasonCode) : reason.getDescription()));
                }

                extId = Extension.invalidityDate;
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
            }

            try
            {
                BigInteger snBigInt = serialNumber.getPositiveValue();
                Object returnedObj = null;
                if(Permission.UNREVOKE_CERT == permission)
                {
                    returnedObj = ca.unrevokeCertificate(snBigInt);
                }
                else if(Permission.REMOVE_CERT == permission)
                {
                    returnedObj = ca.removeCertificate(snBigInt);
                }
                else
                {
                    returnedObj = ca.revokeCertificate(snBigInt, reason, invalidityDate);
                }

                if(returnedObj != null)
                {
                    PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
                    CertId certId = new CertId(new GeneralName(ca.getCASubjectX500Name()), serialNumber);
                    repContentBuilder.add(status, certId);
                    if(childAuditEvent != null)
                    {
                        childAuditEvent.setStatus(AuditStatus.SUCCESSFUL);
                    }
                }
                else
                {
                    PKIStatusInfo status = new PKIStatusInfo(
                            PKIStatus.rejection, new PKIFreeText("cert not exists"),
                            new PKIFailureInfo(PKIFailureInfo.incorrectData));
                    repContentBuilder.add(status);
                    if(childAuditEvent != null)
                    {
                        childAuditEvent.setStatus(AuditStatus.FAILED);
                        childAuditEvent.addEventData(new AuditEventData("message", "cert not exists"));
                    }
                }
            } catch(OperationException e)
            {
                ErrorCode code = e.getErrorCode();
                LOG.warn("{} certificate, OperationException: code={}, message={}",
                        new Object[]{permission.name(), code.name(), e.getErrorMessage()});

                AuditStatus auditStatus;
                String auditMessage;

                int failureInfo;
                switch(code)
                {
                    case CERT_REVOKED:
                        failureInfo = PKIFailureInfo.certRevoked;
                        auditStatus = AuditStatus.FAILED;
                        auditMessage = "CERT_REVOKED";
                        break;
                    case CERT_UNREVOKED:
                        failureInfo = PKIFailureInfo.notAuthorized;
                        auditStatus = AuditStatus.FAILED;
                        auditMessage = "CERT_UNREVOKED";
                        break;
                    case DATABASE_FAILURE:
                        failureInfo = PKIFailureInfo.systemFailure;
                        auditStatus = AuditStatus.ERROR;
                        auditMessage = "DATABASE_FAILURE";
                        break;
                    case NOT_PERMITTED:
                        failureInfo = PKIFailureInfo.notAuthorized;
                        auditStatus = AuditStatus.FAILED;
                        auditMessage = "NOT_PERMITTED";
                        break;
                    case INSUFFICIENT_PERMISSION:
                        failureInfo = PKIFailureInfo.notAuthorized;
                        auditStatus = AuditStatus.ERROR;
                        auditMessage = "INSUFFICIENT_PERMISSION";
                        break;
                    case System_Failure:
                        failureInfo = PKIFailureInfo.systemFailure;
                        auditStatus = AuditStatus.ERROR;
                        auditMessage = "System_Failure";
                        break;
                    case UNKNOWN_CERT:
                        failureInfo = PKIFailureInfo.badCertId;
                        auditStatus = AuditStatus.FAILED;
                        auditMessage = "UNKNOWN_CERT";
                        break;
                    default:
                        failureInfo = PKIFailureInfo.systemFailure;
                        auditStatus = AuditStatus.ERROR;
                        auditMessage = "InternalErrorCode " + e.getErrorCode();
                        break;
                }

                if(childAuditEvent != null)
                {
                    childAuditEvent.setStatus(auditStatus);
                    childAuditEvent.addEventData(new AuditEventData("message", auditMessage));
                }

                String errorMessage = auditMessage;
                PKIStatusInfo status = generateCmpRejectionStatus(failureInfo, errorMessage);
                repContentBuilder.add(status);
            }
        }

        return new PKIBody(PKIBody.TYPE_REVOCATION_REP, repContentBuilder.build());
    }

    private PKIBody confirmCertificates(ASN1OctetString transactionId, CertConfirmContent certConf)
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
                LOG.warn("no cert under transactionId={}, certReqId={} and certHash=0X{}",
                        new Object[]{transactionId, certReqId.getPositiveValue(), Hex.toHexString(certHash)});
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
                    ca.revokeCertificate(serialNumber, CRLReason.CESSATION_OF_OPERATION, new Date());
                } catch (OperationException e)
                {
                    final String msg = "Could not revoke certificate ca=" + ca.getCAInfo().getName() +
                            " serialNumber=" + serialNumber;
                    if(LOG.isWarnEnabled())
                    {
                        LOG.warn(LogUtil.buildExceptionLogFormat(msg), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(msg, e);
                }

                successfull = false;
            }
        }

        // all other certificates should be revoked
        if(revokePendingCertificates(transactionId))
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
                    new PKIStatusInfo(PKIStatus.rejection, null, new PKIFailureInfo(PKIFailureInfo.systemFailure)));

            return new PKIBody(PKIBody.TYPE_ERROR, emc);
        }
    }

    private boolean publishPendingCertificates(ASN1OctetString transactionId)
    {
        Set<CertificateInfo> remainingCerts = pendingCertPool.removeCertificates(transactionId.getOctets());

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

    private boolean revokePendingCertificates(ASN1OctetString transactionId)
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
                    ca.revokeCertificate(remainingCert.getCert().getCert().getSerialNumber(),
                        CRLReason.CESSATION_OF_OPERATION, invalidityDate);
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
        } catch (InvalidKeyException | IllegalStateException | CRMFException e)
        {
            final String message = "verifyPOP";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
        }
        return false;
    }

    @Override
    protected CmpControl getCmpControl()
    {
        CmpControlEntry entry = ca.getCAManager().getCmpControl();
        if(entry != cmpControlEntry)
        {
            cmpControlEntry = entry;
            cmpControl = new CmpControl();
            cmpControl.setConfirmWaitTime(entry.getConfirmWaitTime());
            cmpControl.setMessageBias(entry.getMessageTimeBias());
            cmpControl.setMessageTimeRequired(entry.isMessageTimeRequired());
            cmpControl.setRequireConfirmCert(entry.isRequireConfirmCert());
            cmpControl.setSendCaCert(entry.isSendCaCert());
            cmpControl.setSendResponderCert(entry.isSendResponderCert());
        }
        return cmpControl;
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
                        ca.revokeCertificate(remainingCert.getCert().getCert().getSerialNumber(),
                            CRLReason.CESSATION_OF_OPERATION, invalidityDate);
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
