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

package org.xipki.pki.ca.server.impl.rest;

import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.AuditEvent;
import org.xipki.commons.audit.AuditLevel;
import org.xipki.commons.audit.AuditService;
import org.xipki.commons.audit.AuditServiceRegister;
import org.xipki.commons.audit.AuditStatus;
import org.xipki.commons.common.util.DateUtil;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.RandomUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.CrlReason;
import org.xipki.commons.security.X509Cert;
import org.xipki.pki.ca.api.InsuffientPermissionException;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.RestfulAPIConstants;
import org.xipki.pki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.CaAuditConstants;
import org.xipki.pki.ca.server.impl.CertTemplateData;
import org.xipki.pki.ca.server.impl.ClientCertCache;
import org.xipki.pki.ca.server.impl.HttpRespAuditException;
import org.xipki.pki.ca.server.impl.X509Ca;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderManager;
import org.xipki.pki.ca.server.impl.util.CaUtil;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.Permission;
import org.xipki.pki.ca.server.mgmt.api.RequestorInfo;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class HttpRestServlet extends HttpServlet {
    private static final Logger LOG = LoggerFactory.getLogger(HttpRestServlet.class);

    private static final long serialVersionUID = 1L;

    private CmpResponderManager responderManager;

    private AuditServiceRegister auditServiceRegister;

    private boolean sslCertInHttpHeader;

    public HttpRestServlet() {
    }

    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        doService(true, request, response);
    }

    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        doService(false, request, response);
    }

    private void doService(final boolean perRequest, final HttpServletRequest request,
            final HttpServletResponse response)
            throws ServletException, IOException {
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
                throw new HttpRespAuditException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        null, message, AuditLevel.ERROR, AuditStatus.FAILED);
            }

            String requestUri = request.getRequestURI();
            String servletPath = request.getServletPath();

            String caName = null;
            String command = null;

            X509Ca ca = null;
            int len = servletPath.length();
            if (requestUri.length() > len + 1) {
                String coreUri = URLDecoder.decode(requestUri.substring(len + 1), "UTF-8");
                int sepIndex = coreUri.indexOf('/');
                if (sepIndex == -1 || sepIndex == coreUri.length() - 1) {
                    String message = "invalid requestURI " + requestUri;
                    LOG.error(message);
                    throw new HttpRespAuditException(HttpServletResponse.SC_NOT_FOUND, null,
                            message, AuditLevel.ERROR, AuditStatus.FAILED);
                }

                String caAlias = coreUri.substring(0, sepIndex).toUpperCase();
                command = coreUri.substring(sepIndex + 1);

                caName = responderManager.getCaNameForAlias(caAlias);
                if (caName == null) {
                    caName = caAlias;
                }
                caName = caName.toUpperCase();
                ca = responderManager.getX509CaResponder(caName).getCa();
            }

            if (caName == null || ca == null || ca.getCaInfo().getStatus() != CaStatus.ACTIVE) {
                String message;
                if (caName == null) {
                    message = "no CA is specified";
                } else if (ca == null) {
                    message = "unknown CA '" + caName + "'";
                } else {
                    message = "CA '" + caName + "' is out of service";
                }
                LOG.warn(message);
                throw new HttpRespAuditException(HttpServletResponse.SC_NOT_FOUND, null, message,
                        AuditLevel.INFO, AuditStatus.FAILED);
            }

            event.addEventData(CaAuditConstants.NAME_CA, ca.getCaIdent().getName());
            event.addEventType(command);

            RequestorInfo requestor;
            // Retrieve the user:password
            String hdrValue = request.getHeader("Authorization");
            if (hdrValue != null && hdrValue.startsWith("Basic ")) {
                String user = null;
                byte[] password = null;
                if (hdrValue.length() > 6) {
                    String b64 = hdrValue.substring(6);
                    byte[] userPwd = Base64.decode(b64);
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
                    throw new HttpRespAuditException(HttpServletResponse.SC_UNAUTHORIZED,
                            "invalid Authorization information",
                            AuditLevel.INFO, AuditStatus.FAILED);
                }
                NameId userIdent = ca.authenticateUser(user, password);
                if (userIdent == null) {
                    throw new HttpRespAuditException(HttpServletResponse.SC_UNAUTHORIZED,
                            "could not authencate user", AuditLevel.INFO, AuditStatus.FAILED);
                }
                requestor = ca.getByUserRequestor(userIdent);
            } else {
                X509Certificate clientCert = ClientCertCache.getTlsClientCert(request,
                        sslCertInHttpHeader);
                if (clientCert == null) {
                    throw new HttpRespAuditException(HttpServletResponse.SC_UNAUTHORIZED,
                            null, "no client certificate", AuditLevel.INFO, AuditStatus.FAILED);
                }
                requestor = ca.getRequestor(clientCert);
            }

            if (requestor == null) {
                throw new OperationException(ErrorCode.NOT_PERMITTED, "no requestor specified");
            }

            event.addEventData(CaAuditConstants.NAME_requestor, requestor.getIdent().getName());

            String respCt = null;
            byte[] respBytes = null;

            if (RestfulAPIConstants.CMD_cacert.equalsIgnoreCase(command)) {
                respCt = RestfulAPIConstants.CT_pkix_cert;
                respBytes = ca.getCaInfo().getCertificate().getEncodedCert();
            } else if (RestfulAPIConstants.CMD_enroll_cert.equalsIgnoreCase(command)) {
                String profile = request.getParameter(RestfulAPIConstants.PARAM_profile);
                if (StringUtil.isBlank(profile)) {
                    throw new HttpRespAuditException(HttpServletResponse.SC_BAD_REQUEST, null,
                            "required parameter " + RestfulAPIConstants.PARAM_profile
                            + " not specified", AuditLevel.INFO, AuditStatus.FAILED);
                }
                profile = profile.toUpperCase();

                try {
                    requestor.assertPermitted(Permission.ENROLL_CERT);
                } catch (InsuffientPermissionException ex) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
                }

                if (!requestor.isCertProfilePermitted(profile)) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED,
                            "certProfile " + profile + " is not allowed");
                }

                String ct = request.getContentType();
                if (!RestfulAPIConstants.CT_pkcs10.equalsIgnoreCase(ct)) {
                    String message = "unsupported media type " + ct;
                    throw new HttpRespAuditException(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE,
                            message, AuditLevel.INFO, AuditStatus.FAILED);
                }

                String strNotBefore = request.getParameter(RestfulAPIConstants.PARAM_not_before);
                Date notBefore = (strNotBefore == null) ? null
                        : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotBefore);

                String strNotAfter = request.getParameter(RestfulAPIConstants.PARAM_not_after);
                Date notAfter = (strNotAfter == null) ? null
                        : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotAfter);

                byte[] encodedCsr = IoUtil.read(request.getInputStream());

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

                if (ca.getCaInfo().isSaveRequest()) {
                    long dbId = ca.addRequest(encodedCsr);
                    ca.addRequestCert(dbId, certInfo.getCert().getCertId());
                }

                X509Cert cert = certInfo.getCert();
                if (cert == null) {
                    String message = "could not generate certificate";
                    LOG.warn(message);
                    throw new HttpRespAuditException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                            null, message, AuditLevel.INFO, AuditStatus.FAILED);
                }
                respCt = RestfulAPIConstants.CT_pkix_cert;
                respBytes = cert.getEncodedCert();
            } else if (RestfulAPIConstants.CMD_revoke_cert.equalsIgnoreCase(command)
                    || RestfulAPIConstants.CMD_delete_cert.equalsIgnoreCase(command)) {
                Permission permission;
                if (RestfulAPIConstants.CMD_revoke_cert.equalsIgnoreCase(command)) {
                    permission = Permission.REVOKE_CERT;
                } else {
                    permission = Permission.REMOVE_CERT;
                }
                try {
                    requestor.assertPermitted(permission);
                } catch (InsuffientPermissionException ex) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
                }

                String strCaSha1 = request.getParameter(RestfulAPIConstants.PARAM_ca_sha1);
                if (StringUtil.isBlank(strCaSha1)) {
                    throw new HttpRespAuditException(HttpServletResponse.SC_BAD_REQUEST, null,
                            "required parameter " + RestfulAPIConstants.PARAM_ca_sha1
                            + " not specified", AuditLevel.INFO, AuditStatus.FAILED);
                }

                String strSerialNumber = request.getParameter(
                        RestfulAPIConstants.PARAM_serial_number);
                if (StringUtil.isBlank(strSerialNumber)) {
                    throw new HttpRespAuditException(HttpServletResponse.SC_BAD_REQUEST, null,
                             "required parameter " + RestfulAPIConstants.PARAM_serial_number
                             + " not specified", AuditLevel.INFO, AuditStatus.FAILED);
                }

                if (!strCaSha1.equalsIgnoreCase(ca.getHexSha1OfCert())) {
                    throw new HttpRespAuditException(HttpServletResponse.SC_BAD_REQUEST, null,
                            "unknown " + RestfulAPIConstants.PARAM_ca_sha1,
                            AuditLevel.INFO, AuditStatus.FAILED);
                }

                BigInteger serialNumber = toBigInt(strSerialNumber);

                if (RestfulAPIConstants.CMD_revoke_cert.equalsIgnoreCase(command)) {
                    String strReason = request.getParameter(RestfulAPIConstants.PARAM_reason);
                    CrlReason reason = (strReason == null) ? CrlReason.UNSPECIFIED
                            : CrlReason.forNameOrText(strReason);

                    Date invalidityTime = null;
                    String strInvalidityTime = request.getParameter(
                            RestfulAPIConstants.PARAM_invalidity_time);
                    if (StringUtil.isNotBlank(strInvalidityTime)) {
                        invalidityTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(strInvalidityTime);
                    }

                    ca.revokeCertificate(serialNumber, reason, invalidityTime, msgId);
                } else if (RestfulAPIConstants.CMD_delete_cert.equalsIgnoreCase(command)) {
                    ca.removeCertificate(serialNumber, msgId);
                }
            } else if (RestfulAPIConstants.CMD_crl.equalsIgnoreCase(command)) {
                try {
                    requestor.assertPermitted(Permission.GET_CRL);
                } catch (InsuffientPermissionException ex) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
                }

                String strCrlNumber = request.getParameter(RestfulAPIConstants.PARAM_crl_number);
                BigInteger crlNumber = null;
                if (StringUtil.isNotBlank(strCrlNumber)) {
                    try {
                        crlNumber = toBigInt(strCrlNumber);
                    } catch (NumberFormatException ex) {
                        String message = "invalid crlNumber '" + strCrlNumber + "'";
                        LOG.warn(message);
                        throw new HttpRespAuditException(HttpServletResponse.SC_BAD_REQUEST,
                                null, message, AuditLevel.INFO, AuditStatus.FAILED);
                    }
                }

                X509CRL crl = ca.getCrl(crlNumber);
                if (crl == null) {
                    String message = "could not get CRL";
                    LOG.warn(message);
                    throw new HttpRespAuditException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                            null, message, AuditLevel.INFO, AuditStatus.FAILED);
                }

                respCt = RestfulAPIConstants.CT_pkix_crl;
                respBytes = crl.getEncoded();
            } else if (RestfulAPIConstants.CMD_new_crl.equalsIgnoreCase(command)) {
                try {
                    requestor.assertPermitted(Permission.GEN_CRL);
                } catch (InsuffientPermissionException ex) {
                    throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
                }

                X509CRL crl = ca.generateCrlOnDemand(msgId);
                if (crl == null) {
                    String message = "could not generate CRL";
                    LOG.warn(message);
                    throw new HttpRespAuditException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                            null, message, AuditLevel.INFO, AuditStatus.FAILED);
                }

                respCt = RestfulAPIConstants.CT_pkix_crl;
                respBytes = crl.getEncoded();
            } else {
                String message = "invalid command '" + command + "'";
                LOG.error(message);
                throw new HttpRespAuditException(HttpServletResponse.SC_NOT_FOUND, message,
                        AuditLevel.INFO, AuditStatus.FAILED);
            }

            response.setStatus(HttpServletResponse.SC_OK);
            response.setHeader(RestfulAPIConstants.HEADER_PKISTATUS,
                    RestfulAPIConstants.PKISTATUS_accepted);

            if (StringUtil.isNotBlank(respCt)) {
                response.setContentType(respCt);
            }

            if (respBytes != null) {
                response.setContentLength(respBytes.length);
                response.getOutputStream().write(respBytes);
            }
        } catch (OperationException ex) {
            ErrorCode code = ex.getErrorCode();
            LOG.warn("generate certificate, OperationException: code={}, message={}",
                    code.name(), ex.getErrorMessage());

            int sc;
            String failureInfo;
            switch (code) {
            case ALREADY_ISSUED:
                sc = HttpServletResponse.SC_BAD_REQUEST;
                failureInfo = RestfulAPIConstants.FAILINFO_badRequest;
                break;
            case BAD_CERT_TEMPLATE:
                sc = HttpServletResponse.SC_BAD_REQUEST;
                failureInfo = RestfulAPIConstants.FAILINFO_badCertTemplate;
                break;
            case BAD_REQUEST:
                sc = HttpServletResponse.SC_BAD_REQUEST;
                failureInfo = RestfulAPIConstants.FAILINFO_badRequest;
                break;
            case CERT_REVOKED:
                sc = HttpServletResponse.SC_CONFLICT;
                failureInfo = RestfulAPIConstants.FAILINFO_certRevoked;
                break;
            case CRL_FAILURE:
                sc = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                failureInfo = RestfulAPIConstants.FAILINFO_systemFailure;
                break;
            case DATABASE_FAILURE:
                sc = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                failureInfo = RestfulAPIConstants.FAILINFO_systemFailure;
                break;
            case NOT_PERMITTED:
                sc = HttpServletResponse.SC_UNAUTHORIZED;
                failureInfo = RestfulAPIConstants.FAILINFO_notAuthorized;
                break;
            case INVALID_EXTENSION:
                sc = HttpServletResponse.SC_BAD_REQUEST;
                failureInfo = RestfulAPIConstants.FAILINFO_badRequest;
                break;
            case SYSTEM_FAILURE:
                sc = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                failureInfo = RestfulAPIConstants.FAILINFO_systemFailure;
                break;
            case SYSTEM_UNAVAILABLE:
                sc = HttpServletResponse.SC_SERVICE_UNAVAILABLE;
                failureInfo = RestfulAPIConstants.FAILINFO_systemUnavail;
                break;
            case UNKNOWN_CERT:
                sc = HttpServletResponse.SC_BAD_REQUEST;
                failureInfo = RestfulAPIConstants.FAILINFO_badCertId;
                break;
            case UNKNOWN_CERT_PROFILE:
                sc = HttpServletResponse.SC_BAD_REQUEST;
                failureInfo = RestfulAPIConstants.FAILINFO_badCertTemplate;
                break;
            default:
                sc = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                failureInfo = RestfulAPIConstants.FAILINFO_systemFailure;
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
                auditMessage = code.name() + ": " + ex.getErrorMessage();
                break;
            } // end switch code

            response.setContentLength(0);
            response.setStatus(sc);
            response.setHeader(RestfulAPIConstants.HEADER_PKISTATUS,
                    RestfulAPIConstants.PKISTATUS_rejection);
            if (StringUtil.isNotBlank(failureInfo)) {
                response.setHeader(RestfulAPIConstants.HEADER_failInfo, failureInfo);
            }
        } catch (HttpRespAuditException ex) {
            auditStatus = ex.getAuditStatus();
            auditLevel = ex.getAuditLevel();
            auditMessage = ex.getAuditMessage();
            response.setContentLength(0);
            response.setStatus(ex.getHttpStatus());
        } catch (EOFException ex) {
            LogUtil.warn(LOG, ex, "connection reset by peer");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        } catch (Throwable th) {
            final String message = "Throwable thrown, this should not happen!";
            LogUtil.error(LOG, th, message);

            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.FAILED;
            auditMessage = "internal error";
        } finally {
            try {
                response.flushBuffer();
            } finally {
                audit(auditService, event, auditLevel, auditStatus, auditMessage);
            }
        }
    } // method doService

    public void setResponderManager(final CmpResponderManager responderManager) {
        this.responderManager = responderManager;
    }

    public void setAuditServiceRegister(final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = auditServiceRegister;
    }

    public void setSslCertInHttpHeader(final boolean sslCertInHttpHeader) {
        this.sslCertInHttpHeader = sslCertInHttpHeader;
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
