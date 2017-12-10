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

package org.xipki.ca.server.impl.rest;

import java.io.EOFException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.InsuffientPermissionException;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.api.RestAPIConstants;
import org.xipki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.ca.server.impl.CaAuditConstants;
import org.xipki.ca.server.impl.CertTemplateData;
import org.xipki.ca.server.impl.HttpRespAuditException;
import org.xipki.ca.server.impl.X509Ca;
import org.xipki.ca.server.impl.cmp.CmpResponderManager;
import org.xipki.ca.server.impl.util.CaUtil;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.PermissionConstants;
import org.xipki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.common.util.Base64;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.RandomUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class HttpRestServlet extends AbstractHttpServlet {
    private static final Logger LOG = LoggerFactory.getLogger(HttpRestServlet.class);

    private CmpResponderManager responderManager;

    private AuditServiceRegister auditServiceRegister;

    public HttpRestServlet() {
    }

    @Override
    public boolean needsTlsSessionInfo() {
        return true;
    }

    @Override
    public FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
            SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) {
        HttpVersion version = request.protocolVersion();
        HttpMethod method = request.method();
        if (method != HttpMethod.POST && method != HttpMethod.GET) {
            return createErrorResponse(version, HttpResponseStatus.METHOD_NOT_ALLOWED);
        }

        AuditService auditService = auditServiceRegister.getAuditService();
        AuditEvent event = new AuditEvent(new Date());
        event.setApplicationName(CaAuditConstants.APPNAME);
        event.setName(CaAuditConstants.NAME_PERF);
        event.addEventData(CaAuditConstants.NAME_reqType, RequestType.REST.name());

        String msgId = RandomUtil.nextHexLong();
        event.addEventData(CaAuditConstants.NAME_mid, msgId);

        AuditLevel auditLevel = AuditLevel.INFO;
        AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
        String auditMessage = null;
        try {
            if (responderManager == null) {
                String message = "responderManager in servlet not configured";
                LOG.error(message);
                throw new HttpRespAuditException(HttpResponseStatus.INTERNAL_SERVER_ERROR,
                        null, message, AuditLevel.ERROR, AuditStatus.FAILED);
            }

            String caName = null;
            String command = null;

            X509Ca ca = null;
            if (servletUri.path().length() > 1) {
                // the first char is always '/'
                String coreUri = servletUri.path();
                int sepIndex = coreUri.indexOf('/', 1);
                if (sepIndex == -1 || sepIndex == coreUri.length() - 1) {
                    String message = "invalid requestURI " + request.uri();
                    LOG.error(message);
                    throw new HttpRespAuditException(HttpResponseStatus.NOT_FOUND, null,
                            message, AuditLevel.ERROR, AuditStatus.FAILED);
                }

                // skip also the first char ('/')
                String caAlias = coreUri.substring(1, sepIndex);
                command = coreUri.substring(sepIndex + 1);

                caName = responderManager.getCaNameForAlias(caAlias);
                if (caName == null) {
                    caName = caAlias.toUpperCase();
                }
                ca = responderManager.getX509CaResponder(caName).getCa();
            }

            if (caName == null || ca == null || ca.caInfo().status() != CaStatus.ACTIVE) {
                String message;
                if (caName == null) {
                    message = "no CA is specified";
                } else if (ca == null) {
                    message = "unknown CA '" + caName + "'";
                } else {
                    message = "CA '" + caName + "' is out of service";
                }
                LOG.warn(message);
                throw new HttpRespAuditException(HttpResponseStatus.NOT_FOUND, null, message,
                        AuditLevel.INFO, AuditStatus.FAILED);
            }

            event.addEventData(CaAuditConstants.NAME_CA, ca.caIdent().name());
            event.addEventType(command);

            RequestorInfo requestor;
            // Retrieve the user:password
            String hdrValue = request.headers().get("Authorization");
            if (hdrValue != null && hdrValue.startsWith("Basic ")) {
                String user = null;
                byte[] password = null;
                if (hdrValue.length() > 6) {
                    String b64 = hdrValue.substring(6);
                    byte[] userPwd = Base64.decodeFast(b64);
                    int idx = -1;
                    for (int i = 0; i < userPwd.length; i++) {
                        if (userPwd[i] == ':') {
                            idx = i;
                            break;
                        }
                    }

                    if (idx != -1 && idx < userPwd.length - 1) {
                        user = new String(Arrays.copyOfRange(userPwd, 0, idx));
                        password = Arrays.copyOfRange(userPwd, idx + 1, userPwd.length);
                    }
                }

                if (user == null) {
                    throw new HttpRespAuditException(HttpResponseStatus.UNAUTHORIZED,
                            "invalid Authorization information",
                            AuditLevel.INFO, AuditStatus.FAILED);
                }
                NameId userIdent = ca.authenticateUser(user, password);
                if (userIdent == null) {
                    throw new HttpRespAuditException(HttpResponseStatus.UNAUTHORIZED,
                            "could not authenticate user", AuditLevel.INFO, AuditStatus.FAILED);
                }
                requestor = ca.getByUserRequestor(userIdent);
            } else {
                X509Certificate clientCert =
                        getClientCert(request, sslSession, sslReverseProxyMode);
                if (clientCert == null) {
                    throw new HttpRespAuditException(HttpResponseStatus.UNAUTHORIZED,
                            null, "no client certificate", AuditLevel.INFO, AuditStatus.FAILED);
                }
                requestor = ca.getRequestor(clientCert);
            }

            if (requestor == null) {
                throw new OperationException(ErrorCode.NOT_PERMITTED, "no requestor specified");
            }

            event.addEventData(CaAuditConstants.NAME_requestor, requestor.ident().name());

            String respCt = null;
            byte[] respBytes = null;

            if (RestAPIConstants.CMD_cacert.equalsIgnoreCase(command)) {
                respCt = RestAPIConstants.CT_pkix_cert;
                respBytes = ca.caInfo().certificate().encodedCert();
            } else if (RestAPIConstants.CMD_enroll_cert.equalsIgnoreCase(command)) {
                String profile = servletUri.parameter(RestAPIConstants.PARAM_profile);
                if (StringUtil.isBlank(profile)) {
                    throw new HttpRespAuditException(HttpResponseStatus.BAD_REQUEST, null,
                            "required parameter " + RestAPIConstants.PARAM_profile
                            + " not specified", AuditLevel.INFO, AuditStatus.FAILED);
                }
                profile = profile.toUpperCase();

                try {
                    requestor.assertPermitted(PermissionConstants.ENROLL_CERT);
                } catch (InsuffientPermissionException ex) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
                }

                if (!requestor.isCertProfilePermitted(profile)) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED,
                            "certProfile " + profile + " is not allowed");
                }

                String ct = request.headers().get("Content-Type");
                if (!RestAPIConstants.CT_pkcs10.equalsIgnoreCase(ct)) {
                    String message = "unsupported media type " + ct;
                    throw new HttpRespAuditException(HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE,
                            message, AuditLevel.INFO, AuditStatus.FAILED);
                }

                String strNotBefore = servletUri.parameter(RestAPIConstants.PARAM_not_before);
                Date notBefore = (strNotBefore == null) ? null
                        : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotBefore);

                String strNotAfter = servletUri.parameter(RestAPIConstants.PARAM_not_after);
                Date notAfter = (strNotAfter == null) ? null
                        : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotAfter);

                byte[] encodedCsr = readContent(request);

                CertificationRequest csr = CertificationRequest.getInstance(encodedCsr);
                ca.checkCsr(csr);

                CertificationRequestInfo certTemp = csr.getCertificationRequestInfo();

                X500Name subject = certTemp.getSubject();
                SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

                Extensions extensions = CaUtil.getExtensions(certTemp);
                CertTemplateData certTemplate = new CertTemplateData(subject, publicKeyInfo,
                        notBefore, notAfter, extensions, profile);

                X509CertificateInfo certInfo = ca.generateCertificate(certTemplate,
                        requestor, RequestType.REST, null, msgId);

                if (ca.caInfo().isSaveRequest()) {
                    long dbId = ca.addRequest(encodedCsr);
                    ca.addRequestCert(dbId, certInfo.cert().certId());
                }

                X509Cert cert = certInfo.cert();
                if (cert == null) {
                    String message = "could not generate certificate";
                    LOG.warn(message);
                    throw new HttpRespAuditException(HttpResponseStatus.INTERNAL_SERVER_ERROR,
                            null, message, AuditLevel.INFO, AuditStatus.FAILED);
                }
                respCt = RestAPIConstants.CT_pkix_cert;
                respBytes = cert.encodedCert();
            } else if (RestAPIConstants.CMD_revoke_cert.equalsIgnoreCase(command)
                    || RestAPIConstants.CMD_delete_cert.equalsIgnoreCase(command)) {
                int permission;
                if (RestAPIConstants.CMD_revoke_cert.equalsIgnoreCase(command)) {
                    permission = PermissionConstants.REVOKE_CERT;
                } else {
                    permission = PermissionConstants.REMOVE_CERT;
                }
                try {
                    requestor.assertPermitted(permission);
                } catch (InsuffientPermissionException ex) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
                }

                String strCaSha1 = servletUri.parameter(RestAPIConstants.PARAM_ca_sha1);
                if (StringUtil.isBlank(strCaSha1)) {
                    throw new HttpRespAuditException(HttpResponseStatus.BAD_REQUEST, null,
                            "required parameter " + RestAPIConstants.PARAM_ca_sha1
                            + " not specified", AuditLevel.INFO, AuditStatus.FAILED);
                }

                String strSerialNumber =
                        servletUri.parameter(RestAPIConstants.PARAM_serial_number);
                if (StringUtil.isBlank(strSerialNumber)) {
                    throw new HttpRespAuditException(HttpResponseStatus.BAD_REQUEST, null,
                             "required parameter " + RestAPIConstants.PARAM_serial_number
                             + " not specified", AuditLevel.INFO, AuditStatus.FAILED);
                }

                if (!strCaSha1.equalsIgnoreCase(ca.getHexSha1OfCert())) {
                    throw new HttpRespAuditException(HttpResponseStatus.BAD_REQUEST, null,
                            "unknown " + RestAPIConstants.PARAM_ca_sha1,
                            AuditLevel.INFO, AuditStatus.FAILED);
                }

                BigInteger serialNumber = toBigInt(strSerialNumber);

                if (RestAPIConstants.CMD_revoke_cert.equalsIgnoreCase(command)) {
                    String strReason = servletUri.parameter(RestAPIConstants.PARAM_reason);
                    CrlReason reason = (strReason == null) ? CrlReason.UNSPECIFIED
                            : CrlReason.forNameOrText(strReason);

                    if (reason == CrlReason.REMOVE_FROM_CRL) {
                        ca.unrevokeCertificate(serialNumber, msgId);
                    } else {
                        Date invalidityTime = null;
                        String strInvalidityTime = servletUri.parameter(
                                RestAPIConstants.PARAM_invalidity_time);
                        if (StringUtil.isNotBlank(strInvalidityTime)) {
                            invalidityTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(strInvalidityTime);
                        }

                        ca.revokeCertificate(serialNumber, reason, invalidityTime, msgId);
                    }
                } else if (RestAPIConstants.CMD_delete_cert.equalsIgnoreCase(command)) {
                    ca.removeCertificate(serialNumber, msgId);
                }
            } else if (RestAPIConstants.CMD_crl.equalsIgnoreCase(command)) {
                try {
                    requestor.assertPermitted(PermissionConstants.GET_CRL);
                } catch (InsuffientPermissionException ex) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
                }

                String strCrlNumber = servletUri.parameter(RestAPIConstants.PARAM_crl_number);
                BigInteger crlNumber = null;
                if (StringUtil.isNotBlank(strCrlNumber)) {
                    try {
                        crlNumber = toBigInt(strCrlNumber);
                    } catch (NumberFormatException ex) {
                        String message = "invalid crlNumber '" + strCrlNumber + "'";
                        LOG.warn(message);
                        throw new HttpRespAuditException(HttpResponseStatus.BAD_REQUEST,
                                null, message, AuditLevel.INFO, AuditStatus.FAILED);
                    }
                }

                X509CRL crl = ca.getCrl(crlNumber);
                if (crl == null) {
                    String message = "could not get CRL";
                    LOG.warn(message);
                    throw new HttpRespAuditException(HttpResponseStatus.INTERNAL_SERVER_ERROR,
                            null, message, AuditLevel.INFO, AuditStatus.FAILED);
                }

                respCt = RestAPIConstants.CT_pkix_crl;
                respBytes = crl.getEncoded();
            } else if (RestAPIConstants.CMD_new_crl.equalsIgnoreCase(command)) {
                try {
                    requestor.assertPermitted(PermissionConstants.GEN_CRL);
                } catch (InsuffientPermissionException ex) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
                }

                X509CRL crl = ca.generateCrlOnDemand(msgId);
                if (crl == null) {
                    String message = "could not generate CRL";
                    LOG.warn(message);
                    throw new HttpRespAuditException(HttpResponseStatus.INTERNAL_SERVER_ERROR,
                            null, message, AuditLevel.INFO, AuditStatus.FAILED);
                }

                respCt = RestAPIConstants.CT_pkix_crl;
                respBytes = crl.getEncoded();
            } else {
                String message = "invalid command '" + command + "'";
                LOG.error(message);
                throw new HttpRespAuditException(HttpResponseStatus.NOT_FOUND, message,
                        AuditLevel.INFO, AuditStatus.FAILED);
            }

            FullHttpResponse resp = createOKResponse(version, respCt, respBytes);
            resp.headers().add(RestAPIConstants.HEADER_PKISTATUS,
                    RestAPIConstants.PKISTATUS_accepted);
            return resp;
        } catch (OperationException ex) {
            ErrorCode code = ex.errorCode();
            LOG.warn("generate certificate, OperationException: code={}, message={}",
                    code.name(), ex.errorMessage());

            HttpResponseStatus sc;
            String failureInfo;
            switch (code) {
            case ALREADY_ISSUED:
                sc = HttpResponseStatus.BAD_REQUEST;
                failureInfo = RestAPIConstants.FAILINFO_badRequest;
                break;
            case BAD_CERT_TEMPLATE:
                sc = HttpResponseStatus.BAD_REQUEST;
                failureInfo = RestAPIConstants.FAILINFO_badCertTemplate;
                break;
            case BAD_REQUEST:
                sc = HttpResponseStatus.BAD_REQUEST;
                failureInfo = RestAPIConstants.FAILINFO_badRequest;
                break;
            case CERT_REVOKED:
                sc = HttpResponseStatus.CONFLICT;
                failureInfo = RestAPIConstants.FAILINFO_certRevoked;
                break;
            case CRL_FAILURE:
                sc = HttpResponseStatus.INTERNAL_SERVER_ERROR;
                failureInfo = RestAPIConstants.FAILINFO_systemFailure;
                break;
            case DATABASE_FAILURE:
                sc = HttpResponseStatus.INTERNAL_SERVER_ERROR;
                failureInfo = RestAPIConstants.FAILINFO_systemFailure;
                break;
            case NOT_PERMITTED:
                sc = HttpResponseStatus.UNAUTHORIZED;
                failureInfo = RestAPIConstants.FAILINFO_notAuthorized;
                break;
            case INVALID_EXTENSION:
                sc = HttpResponseStatus.BAD_REQUEST;
                failureInfo = RestAPIConstants.FAILINFO_badRequest;
                break;
            case SYSTEM_FAILURE:
                sc = HttpResponseStatus.INTERNAL_SERVER_ERROR;
                failureInfo = RestAPIConstants.FAILINFO_systemFailure;
                break;
            case SYSTEM_UNAVAILABLE:
                sc = HttpResponseStatus.SERVICE_UNAVAILABLE;
                failureInfo = RestAPIConstants.FAILINFO_systemUnavail;
                break;
            case UNKNOWN_CERT:
                sc = HttpResponseStatus.BAD_REQUEST;
                failureInfo = RestAPIConstants.FAILINFO_badCertId;
                break;
            case UNKNOWN_CERT_PROFILE:
                sc = HttpResponseStatus.BAD_REQUEST;
                failureInfo = RestAPIConstants.FAILINFO_badCertTemplate;
                break;
            default:
                sc = HttpResponseStatus.INTERNAL_SERVER_ERROR;
                failureInfo = RestAPIConstants.FAILINFO_systemFailure;
                break;
            } // end switch (code)

            event.setStatus(AuditStatus.FAILED);
            event.addEventData(CaAuditConstants.NAME_message, code.name());

            switch (code) {
            case DATABASE_FAILURE:
            case SYSTEM_FAILURE:
                auditMessage = code.name();
                break;
            default:
                auditMessage = code.name() + ": " + ex.errorMessage();
                break;
            } // end switch code

            FullHttpResponse resp = createErrorResponse(version, sc);
            resp.headers().add(RestAPIConstants.HEADER_PKISTATUS,
                    RestAPIConstants.PKISTATUS_rejection);
            if (StringUtil.isNotBlank(failureInfo)) {
                resp.headers().add(RestAPIConstants.HEADER_failInfo, failureInfo);
            }
            return resp;
        } catch (HttpRespAuditException ex) {
            auditStatus = ex.auditStatus();
            auditLevel = ex.auditLevel();
            auditMessage = ex.auditMessage();
            return createErrorResponse(version, ex.httpStatus());
        } catch (Throwable th) {
            if (th instanceof EOFException) {
                LogUtil.warn(LOG, th, "connection reset by peer");
            } else {
                LOG.error("Throwable thrown, this should not happen!", th);
            }
            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.FAILED;
            auditMessage = "internal error";
            return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
        } finally {
            audit(auditService, event, auditLevel, auditStatus, auditMessage);
        }
    } // method service

    public void setResponderManager(final CmpResponderManager responderManager) {
        this.responderManager = responderManager;
    }

    public void setAuditServiceRegister(final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = auditServiceRegister;
    }

    private static void audit(final AuditService auditService, final AuditEvent event,
            final AuditLevel auditLevel, final AuditStatus auditStatus, final String auditMessage) {
        if (auditLevel != null) {
            event.setLevel(auditLevel);
        }

        if (auditStatus != null) {
            event.setStatus(auditStatus);
        }

        if (auditMessage != null) {
            event.addEventData(CaAuditConstants.NAME_message, auditMessage);
        }

        event.finish();
        auditService.logEvent(event);
    } // method audit

    private static BigInteger toBigInt(final String str) {
        String tmpStr = str.trim();
        if (tmpStr.startsWith("0x") || tmpStr.startsWith("0X")) {
            if (tmpStr.length() > 2) {
                return new BigInteger(tmpStr.substring(2), 16);
            } else {
                throw new NumberFormatException("invalid integer '" + tmpStr + "'");
            }
        }
        return new BigInteger(tmpStr);
    }

}
