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

package org.xipki.pki.scep.serveremulator;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditStatus;
import org.xipki.common.util.Base64;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.http.servlet.AbstractHttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.pki.scep.exception.MessageDecodingException;
import org.xipki.pki.scep.message.CaCaps;
import org.xipki.pki.scep.message.NextCaMessage;
import org.xipki.pki.scep.transaction.CaCapability;
import org.xipki.pki.scep.transaction.Operation;
import org.xipki.pki.scep.util.ScepConstants;
import org.xipki.security.util.X509Util;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.exe
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepServlet extends AbstractHttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(ScepServlet.class);

    private static final String CT_RESPONSE = ScepConstants.CT_PKI_MESSAGE;

    private AuditService auditService;

    private ScepResponder responder;

    public ScepServlet(final ScepResponder responder) {
        this.responder = ParamUtil.requireNonNull("responder", responder);
    }

    public AuditService auditService() {
        return auditService;
    }

    public void setAuditService(final AuditService auditService) {
        this.auditService = auditService;
    }

    @Override
    public FullHttpResponse service(FullHttpRequest request, ServletURI servletUri,
            SSLSession sslSession, SslReverseProxyMode sslReverseProxyMode) throws Exception {
        HttpVersion version = request.protocolVersion();

        HttpMethod method = request.method();
        boolean post;
        if (HttpMethod.GET.equals(method)) {
            post = false;
        } else if (HttpMethod.POST.equals(method)) {
            post = true;
        } else {
            return createErrorResponse(version, HttpResponseStatus.METHOD_NOT_ALLOWED);
        }

        AuditEvent event = new AuditEvent(new Date());
        event.setApplicationName(ScepAuditConstants.APPNAME);
        event.setName(ScepAuditConstants.NAME_PERF);
        event.addEventData(ScepAuditConstants.NAME_servletPath, request.uri());

        AuditLevel auditLevel = AuditLevel.INFO;
        AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
        String auditMessage = null;

        try {
            CaCaps caCaps = responder.caCaps();
            if (post && !caCaps.containsCapability(CaCapability.POSTPKIOperation)) {
                final String message = "HTTP POST is not supported";
                LOG.error(message);

                auditMessage = message;
                auditStatus = AuditStatus.FAILED;
                return createErrorResponse(version, HttpResponseStatus.BAD_REQUEST);
            }

            String operation = servletUri.parameter("operation");
            event.addEventData(ScepAuditConstants.NAME_operation, operation);

            if ("PKIOperation".equalsIgnoreCase(operation)) {
                CMSSignedData reqMessage;
                // parse the request
                try {
                    byte[] content;
                    if (post) {
                        ByteBuf buf = request.content();
                        content = new byte[buf.readableBytes()];
                        buf.getBytes(buf.readerIndex(), content);
                    } else {
                        String b64 = servletUri.parameter("message");
                        content = Base64.decode(b64);
                    }

                    reqMessage = new CMSSignedData(content);
                } catch (Exception ex) {
                    final String message = "invalid request";
                    LogUtil.error(LOG, ex, message);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                    return createErrorResponse(version, HttpResponseStatus.BAD_REQUEST);
                }

                ContentInfo ci;
                try {
                    ci = responder.servicePkiOperation(reqMessage, event);
                } catch (MessageDecodingException ex) {
                    final String message = "could not decrypt and/or verify the request";
                    LogUtil.error(LOG, ex, message);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                    return createErrorResponse(version, HttpResponseStatus.BAD_REQUEST);
                } catch (CaException ex) {
                    final String message = "system internal error";
                    LogUtil.error(LOG, ex, message);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                    return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
                }
                byte[] respBytes = ci.getEncoded();
                return createOKResponse(version, CT_RESPONSE, respBytes);
            } else if (Operation.GetCACaps.code().equalsIgnoreCase(operation)) {
                // CA-Ident is ignored
                byte[] caCapsBytes = responder.caCaps().bytes();
                return createOKResponse(version, ScepConstants.CT_TEXT_PLAIN, caCapsBytes);
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
                        LogUtil.error(LOG, ex, message);

                        auditMessage = message;
                        auditStatus = AuditStatus.FAILED;
                        return createErrorResponse(version,
                                HttpResponseStatus.INTERNAL_SERVER_ERROR);
                    }
                }

                return createOKResponse(version, ct, respBytes);
            } else if (Operation.GetNextCACert.code().equalsIgnoreCase(operation)) {
                if (responder.nextCaAndRa() == null) {
                    auditMessage = "SCEP operation '" + operation + "' is not permitted";
                    auditStatus = AuditStatus.FAILED;
                    return createErrorResponse(version, HttpResponseStatus.FORBIDDEN);
                }

                try {
                    NextCaMessage nextCaMsg = new NextCaMessage();
                    nextCaMsg.setCaCert(X509Util.toX509Cert(
                            responder.nextCaAndRa().caCert()));
                    if (responder.nextCaAndRa().raCert() != null) {
                        X509Certificate raCert = X509Util.toX509Cert(
                                responder.nextCaAndRa().raCert());
                        nextCaMsg.setRaCerts(Arrays.asList(raCert));
                    }

                    ContentInfo signedData = responder.encode(nextCaMsg);
                    byte[] respBytes = signedData.getEncoded();
                    return createOKResponse(version, ScepConstants.CT_X509_NEXT_CA_CERT, respBytes);
                } catch (Exception ex) {
                    final String message = "system internal error";
                    LogUtil.error(LOG, ex, message);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                    return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
                }
            } else {
                auditMessage = "unknown SCEP operation '" + operation + "'";
                auditStatus = AuditStatus.FAILED;

                return createErrorResponse(version, HttpResponseStatus.BAD_REQUEST);
            } // end if ("PKIOperation".equalsIgnoreCase(operation))
        } catch (EOFException ex) {
            final String message = "connection reset by peer";
            LogUtil.warn(LOG, ex, message);
            return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
        } catch (Throwable th) {
            LOG.error("Throwable thrown, this should not happen!", th);
            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.FAILED;
            auditMessage = "internal error";
            return createErrorResponse(version, HttpResponseStatus.INTERNAL_SERVER_ERROR);
        } finally {
            audit(auditService, event, auditLevel, auditStatus, auditMessage);
        } // end try
    } // method service

    protected PKIMessage generatePkiMessage(final InputStream is) throws IOException {
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

    static void audit(final AuditService auditService, final AuditEvent event,
            final AuditLevel auditLevel, final AuditStatus auditStatus, final String auditMessage) {
        if (auditLevel != null) {
            event.setLevel(auditLevel);
        }

        if (auditStatus != null) {
            event.setStatus(auditStatus);
        }

        if (auditMessage != null) {
            event.addEventData("message", auditMessage);
        }

        event.finish();
        auditService.logEvent(event);
    }

}
