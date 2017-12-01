/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.scep.serveremulator;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;

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
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.message.CaCaps;
import org.xipki.scep.message.NextCaMessage;
import org.xipki.scep.serveremulator.AuditEvent.AuditLevel;
import org.xipki.scep.transaction.CaCapability;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.util.ScepConstants;
import org.xipki.scep.util.ScepUtil;

/**
 * URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.exe
 *
 * @author Lijun Liao
 */

public class ScepServlet extends HttpServlet {

    private static final long serialVersionUID = 7442535012222114067L;

    private static final Logger LOG = LoggerFactory.getLogger(ScepServlet.class);

    private static final String CT_RESPONSE = ScepConstants.CT_PKI_MESSAGE;

    private ScepResponder responder;

    public ScepServlet(final ScepResponder responder) {
        this.responder = ScepUtil.requireNonNull("responder", responder);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        boolean post;

        String method = req.getMethod();
        if ("GET".equals(method)) {
            post = false;
        } else if ("POST".equals(method)) {
            post = true;
        } else {
            resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }

        AuditEvent event = new AuditEvent();
        event.setName(ScepAuditConstants.NAME_PERF);
        event.putEventData(ScepAuditConstants.NAME_servletPath, req.getServletPath());

        AuditLevel auditLevel = AuditLevel.INFO;
        String auditMessage = null;

        try {
            CaCaps caCaps = responder.caCaps();
            if (post && !caCaps.containsCapability(CaCapability.POSTPKIOperation)) {
                final String message = "HTTP POST is not supported";
                LOG.error(message);

                auditMessage = message;
                auditLevel = AuditLevel.ERROR;
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            String operation = req.getParameter("operation");
            event.putEventData(ScepAuditConstants.NAME_operation, operation);

            if ("PKIOperation".equalsIgnoreCase(operation)) {
                CMSSignedData reqMessage;
                // parse the request
                try {
                    byte[] content;
                    if (post) {
                        content = ScepUtil.read(req.getInputStream());
                    } else {
                        String b64 = req.getParameter("message");
                        content = Base64.decode(b64);
                    }

                    reqMessage = new CMSSignedData(content);
                } catch (Exception ex) {
                    final String message = "invalid request";
                    LOG.error(message, LOG);

                    auditMessage = message;
                    auditLevel = AuditLevel.ERROR;
                    resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
                    return;
                }

                ContentInfo ci;
                try {
                    ci = responder.servicePkiOperation(reqMessage, event);
                } catch (MessageDecodingException ex) {
                    final String message = "could not decrypt and/or verify the request";
                    LOG.error(message, ex);

                    auditMessage = message;
                    auditLevel = AuditLevel.ERROR;
                    resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
                    return;
                } catch (CaException ex) {
                    final String message = "system internal error";
                    LOG.error(message, ex);

                    auditMessage = message;
                    auditLevel = AuditLevel.ERROR;
                    resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    return;
                }
                byte[] respBytes = ci.getEncoded();
                sendToResponse(resp, CT_RESPONSE, respBytes);
            } else if (Operation.GetCACaps.code().equalsIgnoreCase(operation)) {
                // CA-Ident is ignored
                byte[] caCapsBytes = responder.caCaps().bytes();
                sendToResponse(resp, ScepConstants.CT_TEXT_PLAIN, caCapsBytes);
            } else if (Operation.GetCACert.code().equalsIgnoreCase(operation)) {
                // CA-Ident is ignored
                byte[] respBytes;
                String ct;
                if (responder.raEmulator() == null) {
                    ct = ScepConstants.CT_X509_CA_CERT;
                    respBytes = responder.caEmulator().caCertBytes();
                } else {
                    ct = ScepConstants.CT_X509_CA_RA_CERT;
                    CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
                    try {
                        cmsSignedDataGen.addCertificate(new X509CertificateHolder(
                                responder.caEmulator().caCert()));
                        ct = ScepConstants.CT_X509_CA_RA_CERT;
                        cmsSignedDataGen.addCertificate(new X509CertificateHolder(
                                responder.raEmulator().raCert()));
                        CMSSignedData degenerateSignedData = cmsSignedDataGen.generate(
                                new CMSAbsentContent());
                        respBytes = degenerateSignedData.getEncoded();
                    } catch (CMSException ex) {
                        final String message = "system internal error";
                        LOG.error(message, ex);

                        auditMessage = message;
                        auditLevel = AuditLevel.ERROR;
                        resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                        return;
                    }
                }

                sendToResponse(resp, ct, respBytes);
            } else if (Operation.GetNextCACert.code().equalsIgnoreCase(operation)) {
                if (responder.nextCaAndRa() == null) {
                    auditMessage = "SCEP operation '" + operation + "' is not permitted";
                    auditLevel = AuditLevel.ERROR;
                    resp.sendError(HttpServletResponse.SC_FORBIDDEN);
                    return;
                }

                try {
                    NextCaMessage nextCaMsg = new NextCaMessage();
                    nextCaMsg.setCaCert(ScepUtil.toX509Cert(
                            responder.nextCaAndRa().caCert()));
                    if (responder.nextCaAndRa().raCert() != null) {
                        X509Certificate raCert = ScepUtil.toX509Cert(
                                responder.nextCaAndRa().raCert());
                        nextCaMsg.setRaCerts(Arrays.asList(raCert));
                    }

                    ContentInfo signedData = responder.encode(nextCaMsg);
                    byte[] respBytes = signedData.getEncoded();
                    sendToResponse(resp, ScepConstants.CT_X509_NEXT_CA_CERT, respBytes);
                } catch (Exception ex) {
                    final String message = "system internal error";
                    LOG.error(message, LOG);

                    auditMessage = message;
                    auditLevel = AuditLevel.ERROR;
                    resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                }
            } else {
                auditMessage = "unknown SCEP operation '" + operation + "'";
                auditLevel = AuditLevel.ERROR;
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            } // end if ("PKIOperation".equalsIgnoreCase(operation))
        } catch (EOFException ex) {
            LOG.warn("connection reset by peer", ex);
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (Throwable th) {
            LOG.error("Throwable thrown, this should not happen!", th);
            auditLevel = AuditLevel.ERROR;
            auditMessage = "internal error";
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } finally {
            if (event.level() != AuditLevel.ERROR) {
                event.setLevel(auditLevel);
            }
            if (auditMessage != null) {
                event.putEventData("error", auditMessage);
            }

            event.log(LOG);
        } // end try
    } // method service

    private void sendToResponse(HttpServletResponse resp, String contentType, byte[] body)
            throws IOException {
        resp.setContentType(contentType);
        resp.setContentLength(body.length);
        resp.getOutputStream().write(body);
    }

    protected PKIMessage generatePkiMessage(final InputStream is) throws IOException {
        ScepUtil.requireNonNull("is", is);
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

}
