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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

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
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.ChildAuditEvent;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.common.CmpControl;
import org.xipki.ca.common.InsuffientPermissionException;
import org.xipki.ca.common.RequestorInfo;
import org.xipki.ca.common.cmp.CmpUtil;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.common.CRLReason;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.CustomObjectIdentifiers;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.IoCertUtil;
import org.xipki.common.LogUtil;
import org.xipki.common.XMLUtil;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class X509CACmpResponder extends CmpResponder
{
    public static final int XiPKI_CRL_REASON_UNREVOKE = 100;
    public static final int XiPKI_CRL_REASON_REMOVE = 101;

    private static final Set<String> knownGenMsgIds = new HashSet<>();

    private static final Logger LOG = LoggerFactory.getLogger(X509CACmpResponder.class);

    private final PendingCertificatePool pendingCertPool;

    private final X509CA ca;
    private final DocumentBuilder xmlDocBuilder;

    static
    {
        knownGenMsgIds.add(CMPObjectIdentifiers.it_currentCRL.getId());
        knownGenMsgIds.add(CustomObjectIdentifiers.id_cmp_generateCRL);
        knownGenMsgIds.add(CustomObjectIdentifiers.id_cmp_getSystemInfo);
        knownGenMsgIds.add(CustomObjectIdentifiers.id_cmp_removeExpiredCerts);
    }

    public X509CACmpResponder(X509CA ca, ConcurrentContentSigner responder, SecurityFactory securityFactory)
    {
        super(responder, securityFactory);

        this.ca = ca;
        this.pendingCertPool = new PendingCertificatePool();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        try
        {
            xmlDocBuilder = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e)
        {
            throw new RuntimeException("Could not create XML document builder", e);
        }

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
                        pendingCertPool.removeCertificates(tid.getOctets());
                        tv = CmpUtil.getImplictConfirmGeneralInfo();
                        successfull = true;
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

                    InfoTypeAndValue itv = null;
                    if(itvs != null && itvs.length > 0)
                    {
                        for(InfoTypeAndValue _itv : itvs)
                        {
                            String itvType = _itv.getInfoType().getId();
                            if(knownGenMsgIds.contains(itvType))
                            {
                                itv = _itv;
                                break;
                            }
                        }
                    }

                    respBody = null;

                    PKIStatus status = PKIStatus.rejection;
                    String statusMessage = null;
                    int failureInfo = PKIFailureInfo.badRequest;

                    if(itv == null)
                    {
                        statusMessage = "PKIBody type " + type + " is only supported with the sub-types "
                                + knownGenMsgIds.toString();
                    }
                    else
                    {
                        InfoTypeAndValue itvResp = null;
                        ASN1ObjectIdentifier infoType = itv.getInfoType();

                        try
                        {
                            if(CMPObjectIdentifiers.it_currentCRL.equals(infoType))
                            {
                                eventType = "CRL_DOWNLOAD";
                                CertificateList crl;
                                checkPermission(_requestor, Permission.GET_CRL);

                                if(itv.getInfoValue() == null)
                                { // as defined in RFC 4210
                                    crl = ca.getCurrentCRL();
                                }
                                else
                                {
                                    // xipki extension
                                    ASN1Integer crlNumber = ASN1Integer.getInstance(itv.getInfoValue());
                                    crl = ca.getCRL(crlNumber.getPositiveValue());
                                }

                                if(crl == null)
                                {
                                    statusMessage = "No CRL is available";
                                    failureInfo = PKIFailureInfo.badRequest;
                                }
                                else
                                {
                                    itvResp = new InfoTypeAndValue(infoType, crl);
                                }
                            }
                            else if(CustomObjectIdentifiers.id_cmp_generateCRL.equals(infoType.getId()))
                            {
                                eventType = "CRL_GEN";

                                checkPermission(_requestor, Permission.GEN_CRL);
                                X509CRL _crl = ca.generateCRLonDemand();
                                if(_crl == null)
                                {
                                    statusMessage = "CRL generation is not activated";
                                    failureInfo = PKIFailureInfo.badRequest;
                                }
                                else
                                {
                                    CertificateList crl = CertificateList.getInstance(_crl.getEncoded());
                                    itvResp = new InfoTypeAndValue(infoType, crl);
                                }
                            }
                            else if(CustomObjectIdentifiers.id_cmp_getSystemInfo.equals(infoType.getId()))
                            {
                                eventType = "GET_SYSTEMINFO";
                                String systemInfo = getSystemInfo(_requestor);
                                itvResp = new InfoTypeAndValue(infoType, new DERUTF8String(systemInfo));
                            }
                            else if(CustomObjectIdentifiers.id_cmp_removeExpiredCerts.equals(infoType.getId()))
                            {
                                eventType = "REMOVE_EXIPIRED_CERTS_TRIGGER";
                                checkPermission(_requestor, Permission.REMOVE_CERT);

                                String info = removeExpiredCerts(_requestor, itv.getInfoValue());
                                itvResp = new InfoTypeAndValue(infoType, new DERUTF8String(info));
                            }
                            else
                            {
                                throw new RuntimeException("should not reach here");
                            }

                            if(itvResp != null)
                            {
                                status = PKIStatus.granted;
                                GenRepContent genRepContent = new GenRepContent(itvResp);
                                respBody = new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
                            }
                        } catch (OperationException e)
                        {
                            failureInfo = PKIFailureInfo.systemFailure;
                            ErrorCode code = e.getErrorCode();
                            switch(code)
                            {
                                case BAD_REQUEST:
                                    failureInfo = PKIFailureInfo.badRequest;
                                    statusMessage = e.getErrorMessage();
                                    break;
                                case DATABASE_FAILURE:
                                case System_Failure:
                                    statusMessage = code.name();
                                    break;
                                default:
                                    statusMessage = code.name() + ": " + e.getErrorMessage();
                                    break;
                            }
                        } catch (CRLException e)
                        {
                            failureInfo = PKIFailureInfo.systemFailure;
                            statusMessage = "CRLException: " + e.getMessage();
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
                org.xipki.ca.common.PKIStatusInfo pkiStatus = new org.xipki.ca.common.PKIStatusInfo(
                        errorMsgContent.getPKIStatusInfo());

                if(pkiStatus.getPkiFailureInfo() == PKIFailureInfo.systemFailure)
                {
                    auditStatus = AuditStatus.ERROR;
                }
                auditEvent.setStatus(auditStatus);

                String statusString = pkiStatus.getStatusMessage();
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
        }catch(OperationException e)
        {
            ErrorCode code = e.getErrorCode();
            LOG.warn("generate certificate, OperationException: code={}, message={}",
                    code.name(), e.getErrorMessage());

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
                case BAD_REQUEST:
                    failureInfo = PKIFailureInfo.badRequest;
                    auditStatus = AuditStatus.ERROR;
                    auditMessage = "BAD_REQUEST";
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
                case System_Unavailable:
                    failureInfo = PKIFailureInfo.systemUnavail;
                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "System_Unavailable";
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
                    auditMessage = "InternalErrorCode " + e.getErrorCode();
                    break;
            }

            if(childAuditEvent != null)
            {
                childAuditEvent.setStatus(auditStatus);
                childAuditEvent.addEventData(new AuditEventData("message", auditMessage));
            }

            String errorMessage;
            switch(code)
            {
                case DATABASE_FAILURE:
                case System_Failure:
                    errorMessage = code.name();
                    break;
                default:
                    errorMessage = code.name() + ": " + e.getErrorMessage();
                    break;
            }
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
                    case BAD_REQUEST:
                        failureInfo = PKIFailureInfo.badRequest;
                        auditStatus = AuditStatus.FAILED;
                        auditMessage = "BAD_REQUEST";
                        break;
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
                    case INSUFFICIENT_PERMISSION:
                        failureInfo = PKIFailureInfo.notAuthorized;
                        auditStatus = AuditStatus.ERROR;
                        auditMessage = "INSUFFICIENT_PERMISSION";
                        break;
                    case NOT_PERMITTED:
                        failureInfo = PKIFailureInfo.notAuthorized;
                        auditStatus = AuditStatus.FAILED;
                        auditMessage = "NOT_PERMITTED";
                        break;
                    case System_Failure:
                        failureInfo = PKIFailureInfo.systemFailure;
                        auditStatus = AuditStatus.ERROR;
                        auditMessage = "System_Failure";
                        break;
                    case System_Unavailable:
                        failureInfo = PKIFailureInfo.systemUnavail;
                        auditStatus = AuditStatus.FAILED;
                        auditMessage = "System_Unavailable";
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

                String errorMessage;
                switch(code)
                {
                    case DATABASE_FAILURE:
                    case System_Failure:
                        errorMessage = code.name();
                        break;
                    default:
                        errorMessage = code.name() + ": " + e.getErrorMessage();
                        break;
                }

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

            if(accept == false)
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

    private String getSystemInfo(CmpRequestorInfo requestor)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
        sb.append("<systemInfo version=\"1\">");
        // CACert
        sb.append("<CACert>");
        sb.append(Base64.toBase64String(ca.getCAInfo().getCertificate().getEncodedCert()));
        sb.append("</CACert>");

        // Profiles
        Set<String> requestorProfiles = requestor.getProfiles();

        Set<String> supportedProfileNames = new HashSet<>();
        Set<String> caProfileNames = ca.getCAManager().getCertProfilesForCA(ca.getCAInfo().getName());
        for(String caProfileName : caProfileNames)
        {
            if(requestorProfiles.contains("all") || requestorProfiles.contains(caProfileName))
            {
                supportedProfileNames.add(caProfileName);
            }
        }

        if(supportedProfileNames.isEmpty() == false)
        {
            sb.append("<certProfiles>");
            for(String name : supportedProfileNames)
            {
                sb.append("<certProfile>");
                sb.append(name);
                sb.append("</certProfile>");
            }

            sb.append("</certProfiles>");
        }

        sb.append("</systemInfo>");
        return sb.toString();
    }

    private String removeExpiredCerts(CmpRequestorInfo requestor, ASN1Encodable asn1RequestInfo)
    throws OperationException, InsuffientPermissionException
    {
        String requestInfo = null;
        try
        {
            DERUTF8String asn1 = DERUTF8String.getInstance(asn1RequestInfo);
            requestInfo = asn1.getString();
        }catch(IllegalArgumentException e)
        {
            throw new OperationException(ErrorCode.BAD_REQUEST, "The content is not of UTF8 String");
        }

        final String namespace = null;
        Document doc;
        try
        {
            doc = xmlDocBuilder.parse(new ByteArrayInputStream(requestInfo.getBytes("UTF-8")));
        } catch (SAXException | IOException e)
        {
            throw new OperationException(ErrorCode.BAD_REQUEST, "Invalid request" + e.getMessage());
        }

        String certProfile = XMLUtil.getValueOfFirstElementChild(doc.getDocumentElement(), namespace, "certProfile");
        if(certProfile == null)
        {
            throw new OperationException(ErrorCode.BAD_REQUEST, "certProfile is not specified");
        }

        // make sure that the requestor is permitted to remove the certificate profiles
        checkPermission(requestor, certProfile);

        String userLike = XMLUtil.getValueOfFirstElementChild(doc.getDocumentElement(), namespace, "userLike");

        String nodeValue = XMLUtil.getValueOfFirstElementChild(doc.getDocumentElement(), namespace, "overlap");

        Long overlapSeconds = null;
        if(nodeValue == null)
        {
            try
            {
                overlapSeconds = Long.parseLong(nodeValue);
            }catch(NumberFormatException e)
            {
                throw new OperationException(ErrorCode.BAD_REQUEST, "Invalid overlap '" + nodeValue + "'");
            }
        }

        RemoveExpiredCertsInfo result = ca.removeExpiredCerts(certProfile, userLike, overlapSeconds);

        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
        sb.append("<removedExpiredCertsResp version=\"1\">");
        // Profile
        certProfile = result.getCertProfile();
        sb.append("<certProfile>");
        sb.append(certProfile);
        sb.append("</certProfile>");

        // Username
        userLike = result.getUserLike();
        if(userLike != null && userLike.isEmpty() == false)
        {
            sb.append("<userLike>");
            sb.append(userLike);
            sb.append("</userLike>");
        }

        // overlap
        sb.append("<overlap>");
        sb.append(result.getOverlap());
        sb.append("</overlap>");

        // expiredAt
        sb.append("<expiredAt>");
        sb.append(result.getExpiredAt());
        sb.append("</expiredAt>");

        // numCerts
        sb.append("<numCerts>");
        sb.append(result.getNumOfCerts());
        sb.append("</numCerts>");

        sb.append("</removedExpiredCertsResp>");

        return sb.toString();
    }

}
