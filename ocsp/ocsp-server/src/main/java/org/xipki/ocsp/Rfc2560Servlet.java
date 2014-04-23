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

package org.xipki.ocsp;

import java.io.IOException;
import java.util.Date;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditStatus;

public class Rfc2560Servlet extends HttpServlet
{
    private final Logger LOG = LoggerFactory.getLogger(Rfc2560Servlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_REQUEST  = "application/ocsp-request";
    private static final String CT_RESPONSE = "application/ocsp-response";

    private int maxRequestLength = 4096;

    private AuditLoggingService auditLoggingService;

    private OcspResponder responder;

    public Rfc2560Servlet()
    {
    }

    public void setResponder(OcspResponder responder)
    {
        this.responder = responder;
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        AuditEvent auditEvent = null;

        AuditLevel auditLevel = AuditLevel.INFO;
        AuditStatus auditStatus = AuditStatus.successfull;
        String auditMessage = null;

        long startInUs = 0;

        if(auditLoggingService != null)
        {
            startInUs = System.nanoTime()/1000;
            auditEvent = new AuditEvent(new Date());
            auditEvent.setApplicationName("OCSP");
            auditEvent.setName("SYSTEM");
        }

        try
        {
            if(responder == null)
            {
                String message = "responder in servlet not configured";
                LOG.error(message);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);

                auditLevel = AuditLevel.ERROR;
                auditStatus = AuditStatus.failed;
                auditMessage = message;
                return;
            }

            // accept only "application/ocsp-request" as content type
            if (CT_REQUEST.equalsIgnoreCase(request.getContentType()) == false)
            {
                response.setContentLength(0);
                response.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);

                auditStatus = AuditStatus.failed;
                auditMessage = "unsupporte media type " + request.getContentType();
                return;
            }

            // request too long
            if(request.getContentLength() > maxRequestLength)
            {
                response.setContentLength(0);
                response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);

                auditStatus = AuditStatus.failed;
                auditMessage = "request too large";
                return;
            }

            ServletInputStream in = request.getInputStream();
            ASN1StreamParser parser = new ASN1StreamParser(in);
            OCSPRequest ocspRequest = OCSPRequest.getInstance(parser.readObject());
            OCSPReq ocspReq = new OCSPReq(ocspRequest);

            response.setContentType(Rfc2560Servlet.CT_RESPONSE);

            OCSPResp ocspResp = responder.answer(ocspReq, auditEvent);
            if (ocspResp == null)
            {
                auditMessage = "processRequest returned null, this should not happen";
                LOG.error(auditMessage);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);

                auditLevel = AuditLevel.ERROR;
                auditStatus = AuditStatus.error;
            }
            else
            {
                byte[] encodedOcspResp = ocspResp.getEncoded();
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentLength(encodedOcspResp.length);
                response.getOutputStream().write(encodedOcspResp);
            }
        }catch(Throwable t)
        {
            LOG.error("Throwable. {}: {}", t.getClass().getName(), t.getMessage());
            LOG.debug("Throwable", t);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);

            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.error;
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

                    long durationInUs = System.nanoTime() / 1000 - startInUs;
                    String durationText;
                    if(durationInUs > 5000)
                    {
                        durationText = Long.toString(durationInUs / 1000);
                    }
                    else
                    {
                        durationText = Double.toString(Double.valueOf(durationInUs) / 1000);
                    }

                    auditEvent.addEventData(new AuditEventData("duration",
                            durationText));

                    if(auditEvent.containsChildAuditEvents() == false)
                    {
                        auditLoggingService.logEvent(auditEvent);
                    }
                    else
                    {
                        List<AuditEvent> expandedAuditEvents = auditEvent.expandAuditEvents();
                        for(AuditEvent event : expandedAuditEvents)
                        {
                            auditLoggingService.logEvent(event);
                        }
                    }
                }
            }
        }

    }

    public int getMaxRequestLength()
    {
        return maxRequestLength;
    }

    public void setMaxRequestLength(int maxRequestLength)
    {
        this.maxRequestLength = maxRequestLength;
    }

    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;
    }

}
