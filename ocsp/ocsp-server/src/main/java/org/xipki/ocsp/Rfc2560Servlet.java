/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.audit.api.AuditStatus;
import org.xipki.ocsp.OCSPRespWithCacheInfo.ResponseCacheInfo;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.LogUtil;

/**
 * @author Lijun Liao
 */

public class Rfc2560Servlet extends HttpServlet
{
    private final Logger LOG = LoggerFactory.getLogger(Rfc2560Servlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_REQUEST  = "application/ocsp-request";
    private static final String CT_RESPONSE = "application/ocsp-response";

    private AuditLoggingServiceRegister auditServiceRegister;

    private OcspResponder responder;

    public Rfc2560Servlet()
    {
    }

    public void setResponder(OcspResponder responder)
    {
        this.responder = responder;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        if(responder != null || responder.supportsHttpGet())
        {
            processRequest(request, response, true);
        }
        else
        {
            super.doGet(request, response);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        processRequest(request, response, false);
    }

    private void processRequest(HttpServletRequest request, HttpServletResponse response, boolean getMethod)
    throws ServletException, IOException
    {
        AuditEvent auditEvent = null;

        AuditLevel auditLevel = AuditLevel.INFO;
        AuditStatus auditStatus = AuditStatus.SUCCSEEFULL;
        String auditMessage = null;

        long startInUs = 0;

        AuditLoggingService auditLoggingService = auditServiceRegister == null ? null :
            auditServiceRegister.getAuditLoggingService();

        if(auditLoggingService != null && responder.isAuditResponse())
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
                auditStatus = AuditStatus.FAILED;
                auditMessage = message;
                return;
            }

            OCSPRequest ocspRequest;
            if(getMethod)
            {
                String requestURI = request.getRequestURI();
                String servletPath = request.getServletPath();
                if(servletPath.endsWith("/") == false)
                {
                    servletPath += "/";
                }

                // RFC2560 A.1.1 specifies that request longer than 255 bytes SHOULD be sent by POST,
                // we support GET for longer requests anyway.
                if(requestURI.length() > responder.getMaxRequestSize() + servletPath.length())
                {
                    response.setContentLength(0);
                    response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);

                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "request too large";
                    return;
                }

                int indexOf = requestURI.indexOf(servletPath);

                String b64Request;
                if (indexOf >= 0)
                {
                    b64Request = requestURI.substring(indexOf+servletPath.length());
                }
                else
                {
                    b64Request = requestURI;
                }

                ocspRequest = OCSPRequest.getInstance(Base64.decode(b64Request));
            }
            else
            {
                // accept only "application/ocsp-request" as content type
                if (CT_REQUEST.equalsIgnoreCase(request.getContentType()) == false)
                {
                    response.setContentLength(0);
                    response.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);

                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "unsupporte media type " + request.getContentType();
                    return;
                }

                // request too long
                if(request.getContentLength() > responder.getMaxRequestSize())
                {
                    response.setContentLength(0);
                    response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);

                    auditStatus = AuditStatus.FAILED;
                    auditMessage = "request too large";
                    return;
                }
                ServletInputStream in = request.getInputStream();
                ASN1StreamParser parser = new ASN1StreamParser(in);
                ocspRequest = OCSPRequest.getInstance(parser.readObject());
            }

            OCSPReq ocspReq = new OCSPReq(ocspRequest);

            response.setContentType(Rfc2560Servlet.CT_RESPONSE);

            OCSPRespWithCacheInfo ocspRespWithCacheInfo = responder.answer(ocspReq, auditEvent, getMethod);
            if (ocspRespWithCacheInfo == null)
            {
                auditMessage = "processRequest returned null, this should not happen";
                LOG.error(auditMessage);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);

                auditLevel = AuditLevel.ERROR;
                auditStatus = AuditStatus.ERROR;
            }
            else
            {
                OCSPResp resp =ocspRespWithCacheInfo.getResponse();
                byte[] encodedOcspResp = resp.getEncoded();
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentLength(encodedOcspResp.length);

                ResponseCacheInfo cacheInfo = ocspRespWithCacheInfo.getCacheInfo();
                if(getMethod && cacheInfo != null)
                {
                    long now = System.currentTimeMillis();
                    // RFC 5019 6.2: Date: The date and time at which the OCSP server generated the HTTP response.
                    response.setDateHeader("Date", now);
                    // RFC 5019 6.2: Last-Modified: date and time at which the OCSP responder last modified the response.
                    response.setDateHeader("Last-Modified", cacheInfo.getThisUpdate());
                    // RFC 5019 6.2: Expires: This date and time will be the same as the nextUpdate time-stamp in the OCSP
                    // response itself.
                    // This is overridden by max-age on HTTP/1.1 compatible components
                    if(cacheInfo.getNextUpdate() != null)
                    {
                        response.setDateHeader("Expires", cacheInfo.getNextUpdate());
                    }
                    // RFC 5019 6.2: This profile RECOMMENDS that the ETag value be the ASCII HEX representation of the
                    // SHA1 hash of the OCSPResponse structure.
                    response.setHeader("ETag", "\"" + IoCertUtil.sha1sum(encodedOcspResp).toLowerCase() + "\"");

                    // Max age must be in seconds in the cache-control header
                    long maxAge;
                    if(responder.getCachMaxAge() != null)
                    {
                        maxAge = responder.getCachMaxAge().longValue();
                    }
                    else
                    {
                        maxAge = responder.getDefaultCacheMaxAge();
                    }

                    if(cacheInfo.getNextUpdate() != null)
                    {
                        maxAge = Math.min(maxAge, (cacheInfo.getNextUpdate() - cacheInfo.getThisUpdate()) / 1000);
                    }

                    response.setHeader("Cache-Control", "max-age=" + maxAge + ",public,no-transform,must-revalidate");
                }
                response.getOutputStream().write(encodedOcspResp);
            }
        }catch(Throwable t)
        {
            final String message = "Throwable";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
            }
            LOG.debug(message, t);

            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);

            auditLevel = AuditLevel.ERROR;
            auditStatus = AuditStatus.ERROR;
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

    public void setAuditServiceRegister(AuditLoggingServiceRegister auditServiceRegister)
    {
        this.auditServiceRegister = auditServiceRegister;
    }

}
