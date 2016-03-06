/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.scep.serveremulator;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.api.AuditEvent;
import org.xipki.commons.audit.api.AuditEventData;
import org.xipki.commons.audit.api.AuditLevel;
import org.xipki.commons.audit.api.AuditService;
import org.xipki.commons.audit.api.AuditStatus;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.scep.exception.MessageDecodingException;
import org.xipki.pki.scep.message.CaCaps;
import org.xipki.pki.scep.message.NextCaMessage;
import org.xipki.pki.scep.transaction.CaCapability;
import org.xipki.pki.scep.transaction.Operation;
import org.xipki.pki.scep.util.ScepConstants;
import org.xipki.pki.scep.util.ScepUtil;

/**
 * URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.exe
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepServlet extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(ScepServlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_RESPONSE = ScepConstants.CT_PKI_MESSAGE;

    private AuditService auditService;

    private ScepResponder responder;

    public ScepServlet(
            final ScepResponder responder) {
        this.responder = ParamUtil.requireNonNull("responder", responder);
    }

    public AuditService getAuditService() {
        return auditService;
    }

    public void setAuditService(
            final AuditService auditService) {
        this.auditService = auditService;
    }

    @Override
    public void doGet(
            final HttpServletRequest request,
            final HttpServletResponse response)
    throws ServletException, IOException {
        service(request, response, false);
    }

    @Override
    public void doPost(
            final HttpServletRequest request,
            final HttpServletResponse response)
    throws ServletException, IOException {
        service(request, response, true);
    }

    private void service(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final boolean post)
    throws ServletException, IOException {
        String servletPath = request.getServletPath();

        AuditEvent auditEvent = (auditService != null)
                ? new AuditEvent(new Date())
                : null;
        if (auditEvent != null) {
            auditEvent.setApplicationName("SCEP");
            auditEvent.setName("PERF");
            auditEvent.addEventData(new AuditEventData("servletPath", servletPath));
        }

        AuditLevel auditLevel = AuditLevel.INFO;
        AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
        String auditMessage = null;

        OutputStream respStream = response.getOutputStream();

        try {
            CaCaps caCaps = responder.getCaCaps();
            if (post && !caCaps.containsCapability(CaCapability.POSTPKIOperation)) {
                final String message = "HTTP POST is not supported";
                LOG.error(message);

                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.setContentLength(0);

                auditMessage = message;
                auditStatus = AuditStatus.FAILED;
                return;
            }

            String operation = request.getParameter("operation");
            auditEvent.addEventData(new AuditEventData("operation", operation));

            if ("PKIOperation".equalsIgnoreCase(operation)) {
                CMSSignedData reqMessage;
                // parse the request
                try {
                    byte[] content;
                    if (post) {
                        content = ScepUtil.read(request.getInputStream());
                    } else {
                        String b64 = request.getParameter("message");
                        content = Base64.decode(b64);
                    }

                    reqMessage = new CMSSignedData(content);
                } catch (Exception ex) {
                    final String message = "invalid request";
                    if (LOG.isErrorEnabled()) {
                        LOG.error(ScepUtil.buildExceptionLogFormat(message),
                                ex.getClass().getName(), ex.getMessage());
                    }
                    LOG.debug(message, ex);

                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    response.setContentLength(0);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                    return;
                }

                ContentInfo ci;
                try {
                    ci = responder.servicePkiOperation(reqMessage, auditEvent);
                } catch (MessageDecodingException ex) {
                    final String message = "could not decrypt and/or verify the request";
                    if (LOG.isErrorEnabled()) {
                        LOG.error(ScepUtil.buildExceptionLogFormat(message),
                                ex.getClass().getName(), ex.getMessage());
                    }
                    LOG.debug(message, ex);

                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    response.setContentLength(0);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                    return;
                } catch (CaException ex) {
                    final String message = "system internal error";
                    if (LOG.isErrorEnabled()) {
                        LOG.error(ScepUtil.buildExceptionLogFormat(message),
                                ex.getClass().getName(), ex.getMessage());
                    }
                    LOG.debug(message, ex);

                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    response.setContentLength(0);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                    return;
                }
                byte[] respBytes = ci.getEncoded();
                response.setContentType(CT_RESPONSE);
                response.setContentLength(respBytes.length);
                respStream.write(respBytes);
            } else if (Operation.GetCACaps.getCode().equalsIgnoreCase(operation)) {
                // CA-Ident is ignored
                response.setContentType(ScepConstants.CT_TEXT_PLAIN);
                byte[] caCapsBytes = responder.getCaCaps().getBytes();
                respStream.write(caCapsBytes);
                response.setContentLength(caCapsBytes.length);
            } else if (Operation.GetCACert.getCode().equalsIgnoreCase(operation)) {
                // CA-Ident is ignored
                byte[] respBytes;
                String ct;
                if (responder.getRaEmulator() == null) {
                    ct = ScepConstants.CT_X509_CA_CERT;
                    respBytes = responder.getCaEmulator().getCaCertBytes();
                } else {
                    ct = ScepConstants.CT_X509_CA_RA_CERT;
                    CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
                    try {
                        cmsSignedDataGen.addCertificate(new X509CertificateHolder(
                                responder.getCaEmulator().getCaCert()));
                        ct = ScepConstants.CT_X509_CA_RA_CERT;
                        cmsSignedDataGen.addCertificate(new X509CertificateHolder(
                                responder.getRaEmulator().getRaCert()));
                        CMSSignedData degenerateSignedData = cmsSignedDataGen.generate(
                                new CMSAbsentContent());
                        respBytes = degenerateSignedData.getEncoded();
                    } catch (CMSException ex) {
                        final String message = "system internal error";
                        if (LOG.isErrorEnabled()) {
                            LOG.error(ScepUtil.buildExceptionLogFormat(message),
                                    ex.getClass().getName(), ex.getMessage());
                        }
                        LOG.debug(message, ex);

                        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                        response.setContentLength(0);

                        auditMessage = message;
                        auditStatus = AuditStatus.FAILED;
                        return;
                    }
                } // end if (responder.getRAEmulator() == null) {
                response.setContentType(ct);
                response.setContentLength(respBytes.length);
                respStream.write(respBytes);
            } else if (Operation.GetNextCACert.getCode().equalsIgnoreCase(operation)) {
                if (responder.getNextCaAndRa() == null) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentLength(0);

                    auditMessage = "SCEP operation '" + operation + "' is not permitted";
                    auditStatus = AuditStatus.FAILED;
                    return;
                }

                try {
                    NextCaMessage nextCaMsg = new NextCaMessage();
                    nextCaMsg.setCaCert(
                            new X509CertificateObject(responder.getNextCaAndRa().getCaCert()));
                    if (responder.getNextCaAndRa().getRaCert() != null) {
                        X509Certificate raCert = new X509CertificateObject(
                                responder.getNextCaAndRa().getRaCert());
                        nextCaMsg.setRaCerts(Arrays.asList(raCert));
                    }

                    ContentInfo signedData = responder.encode(nextCaMsg);
                    byte[] respBytes = signedData.getEncoded();
                    response.setContentType(ScepConstants.CT_X509_NEXT_CA_CERT);
                    response.setContentLength(respBytes.length);
                    response.getOutputStream().write(respBytes);
                } catch (Exception ex) {
                    final String message = "system internal error";
                    if (LOG.isErrorEnabled()) {
                        LOG.error(ScepUtil.buildExceptionLogFormat(message),
                                ex.getClass().getName(),
                                ex.getMessage());
                    }
                    LOG.debug(message, ex);

                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    response.setContentLength(0);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                }
            } else {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.setContentLength(0);

                auditMessage = "unknown SCEP operation '" + operation + "'";
                auditStatus = AuditStatus.FAILED;
            } // end if ("PKIOperation".equalsIgnoreCase(operation))
        } catch (EOFException ex) {
            final String message = "connection reset by peer";
            if (LOG.isErrorEnabled()) {
                LOG.warn(ScepUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);

            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        } catch (Throwable th) {
            final String message = "Throwable thrown, this should not happen!";
            LOG.error(message, th);

            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.FAILED;
            auditMessage = "internal error";
        } finally {
            try {
                response.flushBuffer();
            } finally {
                if (auditEvent != null) {
                    audit(auditService, auditEvent, auditLevel, auditStatus, auditMessage);
                }
            }
        } // end try
    } // method service

    protected PKIMessage generatePkiMessage(
            final InputStream is)
    throws IOException {
        ParamUtil.requireNonNull("is", is);
        ASN1InputStream asn1Stream = new ASN1InputStream(is);

        try {
            return PKIMessage.getInstance(asn1Stream.readObject());
        } finally {
            try {
                asn1Stream.close();
            } catch (Exception ex) {
                LOG.error("could not close stream: {}", ex.getMessage());
            }
        }
    }

    static void audit(
            final AuditService auditService,
            final AuditEvent auditEvent,
            final AuditLevel auditLevel,
            final AuditStatus auditStatus,
            final String auditMessage) {
        if (auditLevel != null) {
            auditEvent.setLevel(auditLevel);
        }

        if (auditStatus != null) {
            auditEvent.setStatus(auditStatus);
        }

        if (auditMessage != null) {
            auditEvent.addEventData(new AuditEventData("message", auditMessage));
        }

        auditEvent.setDuration(System.currentTimeMillis() - auditEvent.getTimestamp().getTime());
        auditService.logEvent(auditEvent);
    }

}
