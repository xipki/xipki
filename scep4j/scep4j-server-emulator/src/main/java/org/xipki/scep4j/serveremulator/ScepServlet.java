/*
 * Copyright (c) 2015 Lijun Liao
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

package org.xipki.scep4j.serveremulator;

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
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditStatus;
import org.xipki.scep4j.exception.MessageDecodingException;
import org.xipki.scep4j.message.CACaps;
import org.xipki.scep4j.message.NextCAMessage;
import org.xipki.scep4j.transaction.CACapability;
import org.xipki.scep4j.transaction.Operation;
import org.xipki.scep4j.util.ParamUtil;
import org.xipki.scep4j.util.ScepConstants;
import org.xipki.scep4j.util.ScepUtil;

/**
 * URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.exe
 *
 * @author Lijun Liao
 */

public class ScepServlet extends HttpServlet
{
    private static final Logger LOG = LoggerFactory.getLogger(ScepServlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_RESPONSE = ScepConstants.CT_x_pki_message;

    private AuditLoggingService auditLoggingService;
    private ScepResponder responder;

    public ScepServlet(
            final ScepResponder responder)
    {
        ParamUtil.assertNotNull("responder", responder);
        this.responder = responder;
    }

    public AuditLoggingService getAuditLoggingService()
    {
        return auditLoggingService;
    }

    public void setAuditLoggingService(
            final AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;
    }

    @Override
    public void doGet(
            final HttpServletRequest request,
            final HttpServletResponse response)
    throws ServletException, IOException
    {
        service(request, response, false);
    }

    @Override
    public void doPost(
            final HttpServletRequest request,
            final HttpServletResponse response)
    throws ServletException, IOException
    {
        service(request, response, true);
    }

    private void service(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final boolean post)
    throws ServletException, IOException
    {
        String servletPath = request.getServletPath();

        AuditEvent auditEvent = (auditLoggingService != null) ? new AuditEvent(new Date()) : null;
        if(auditEvent != null)
        {
            auditEvent.setApplicationName("SCEP");
            auditEvent.setName("PERF");
            auditEvent.addEventData(new AuditEventData("servletPath", servletPath));
        }

        AuditLevel auditLevel = AuditLevel.INFO;
        AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
        String auditMessage = null;

        OutputStream respStream = response.getOutputStream();

        try
        {
            CACaps cACaps = responder.getCACaps();
            if(post && cACaps.containsCapability(CACapability.POSTPKIOperation) == false)
            {
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

            if("PKIOperation".equalsIgnoreCase(operation))
            {
                CMSSignedData reqMessage;
                // parse the request
                try
                {
                    byte[] content;
                    if(post)
                    {
                        content = ScepUtil.read(request.getInputStream());
                    } else
                    {
                        String b64 = request.getParameter("message");
                        content = Base64.decode(b64);
                    }

                    reqMessage = new CMSSignedData(content);
                }catch(Exception e)
                {
                    final String message = "invalid request";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(ScepUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);

                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    response.setContentLength(0);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                    return;
                }

                ContentInfo ci;
                try
                {
                    ci = responder.servicePkiOperation(reqMessage, auditEvent);
                } catch (MessageDecodingException e)
                {
                    final String message = "could not decrypt and/or verify the request";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(ScepUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);

                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    response.setContentLength(0);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                    return;
                } catch (CAException e)
                {
                    final String message = "system internal error";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(ScepUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);

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
            }
            else if(Operation.GetCACaps.getCode().equalsIgnoreCase(operation))
            {
                // CA-Ident is ignored
                response.setContentType(ScepConstants.CT_text_palin);
                byte[] caCapsBytes = responder.getCACaps().getBytes();
                respStream.write(caCapsBytes);
                response.setContentLength(caCapsBytes.length);
            }
            else if(Operation.GetCACert.getCode().equalsIgnoreCase(operation))
            {
                // CA-Ident is ignored
                byte[] respBytes;
                String ct;
                if(responder.getRAEmulator() == null)
                {
                    ct = ScepConstants.CT_x_x509_ca_cert;
                    respBytes = responder.getCAEmulator().getCACertBytes();
                }
                else
                {
                    ct = ScepConstants.CT_x_x509_ca_ra_cert;
                    CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
                    try
                    {
                        cmsSignedDataGen.addCertificate(new X509CertificateHolder(responder.getCAEmulator().getCACert()));
                        ct = ScepConstants.CT_x_x509_ca_ra_cert;
                        cmsSignedDataGen.addCertificate(new X509CertificateHolder(responder.getRAEmulator().getRACert()));
                        CMSSignedData degenerateSignedData = cmsSignedDataGen.generate(new CMSAbsentContent());
                        respBytes = degenerateSignedData.getEncoded();
                    } catch (CMSException e)
                    {
                        final String message = "system internal error";
                        if(LOG.isErrorEnabled())
                        {
                            LOG.error(ScepUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                        }
                        LOG.debug(message, e);

                        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                        response.setContentLength(0);

                        auditMessage = message;
                        auditStatus = AuditStatus.FAILED;
                        return;
                    }
                }
                response.setContentType(ct);
                response.setContentLength(respBytes.length);
                respStream.write(respBytes);
            }
            else if(Operation.GetNextCACert.getCode().equalsIgnoreCase(operation))
            {
                if(responder.getNextCAandRA() == null)
                {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentLength(0);

                    auditMessage = "SCEP operation '" + operation + "' is not permitted";
                    auditStatus = AuditStatus.FAILED;
                    return;
                }

                try
                {
                    NextCAMessage nextCAMsg = new NextCAMessage();
                    nextCAMsg.setCaCert(
                            new X509CertificateObject(responder.getNextCAandRA().getCACert()));
                    if(responder.getNextCAandRA().getRACert() != null)
                    {
                        X509Certificate raCert = new X509CertificateObject(responder.getNextCAandRA().getRACert());
                        nextCAMsg.setRaCerts(Arrays.asList(raCert));
                    }

                    ContentInfo signedData = responder.encode(nextCAMsg);
                    byte[] respBytes = signedData.getEncoded();
                    response.setContentType(ScepConstants.CT_x_x509_next_ca_cert);
                    response.setContentLength(respBytes.length);
                    response.getOutputStream().write(respBytes);
                }catch(Exception e)
                {
                    final String message = "system internal error";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(ScepUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);

                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    response.setContentLength(0);

                    auditMessage = message;
                    auditStatus = AuditStatus.FAILED;
                }
            }
            else
            {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.setContentLength(0);

                auditMessage = "unknown SCEP operation '" + operation + "'";
                auditStatus = AuditStatus.FAILED;
            }
        }catch(EOFException e)
        {
            final String message = "connection reset by peer";
            if(LOG.isErrorEnabled())
            {
                LOG.warn(ScepUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);

            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        }catch(Throwable t)
        {
            final String message = "Throwable thrown, this should not happen!";
            LOG.error(message, t);

            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.FAILED;
            auditMessage = "internal error";
        }
        finally
        {
            try
            {
                response.flushBuffer();
            }finally
            {
                if(auditEvent != null)
                {
                    audit(auditLoggingService, auditEvent, auditLevel, auditStatus, auditMessage);
                }
            }
        }
    }

    protected PKIMessage generatePKIMessage(
            final InputStream is)
    throws IOException
    {
        ASN1InputStream asn1Stream = new ASN1InputStream(is);

        try
        {
            return PKIMessage.getInstance(asn1Stream.readObject());
        }finally
        {
            try
            {
                asn1Stream.close();
            }catch(Exception e){}
        }
    }

    static void audit(
            final AuditLoggingService auditLoggingService,
            final AuditEvent auditEvent,
            final AuditLevel auditLevel,
            final AuditStatus auditStatus,
            final String auditMessage)
    {
        if(auditLevel != null)
        {
            auditEvent.setLevel(auditLevel);
        }

        if(auditStatus != null)
        {
            auditEvent.setStatus(auditStatus);
        }

        if(auditMessage != null)
        {
            auditEvent.addEventData(new AuditEventData("message", auditMessage));
        }

        auditEvent.setDuration(System.currentTimeMillis() - auditEvent.getTimestamp().getTime());
        auditLoggingService.logEvent(auditEvent);
    }

}
