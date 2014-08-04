/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.audit.api.AuditStatus;
import org.xipki.ca.server.mgmt.CAManager;
import org.xipki.security.common.LogUtil;

/**
 * @author Lijun Liao
 */

public class Rfc6712Servlet extends HttpServlet
{
    private static final Logger LOG = LoggerFactory.getLogger(Rfc6712Servlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_REQUEST  = "application/pkixcmp";
    private static final String CT_RESPONSE = "application/pkixcmp";

    private CAManager caManager;
    private AuditLoggingServiceRegister auditServiceRegister;

    public Rfc6712Servlet()
    {
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        X509Certificate clientCert = (certs == null || certs.length < 1)? null : certs[0];

        AuditLoggingService auditLoggingService = auditServiceRegister.getAuditLoggingService();
        AuditEvent auditEvent = (auditLoggingService != null) ? new AuditEvent(new Date()) : null;
        if(auditEvent != null)
        {
            auditEvent.setApplicationName("CA");
            auditEvent.setName("SYSTEM");
        }

        AuditLevel auditLevel = AuditLevel.INFO;
        AuditStatus auditStatus = null;
        String auditMessage = null;
        try
        {
            if(caManager == null)
            {
                String message = "caManager in servlet not configured";
                LOG.error(message);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);

                auditLevel = AuditLevel.ERROR;
                auditStatus = AuditStatus.FAILED;
                auditMessage = message;
                return;
            }

            if (CT_REQUEST.equalsIgnoreCase(request.getContentType()) == false)
            {
                response.setContentLength(0);
                response.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);

                auditStatus = AuditStatus.FAILED;
                auditMessage = "unsupporte media type " + request.getContentType();
                return;
            }

            String encodedUrl = request.getRequestURI();
            String constructedPath = null;
            if (encodedUrl != null)
            {
                constructedPath = URLDecoder.decode(encodedUrl, "UTF-8");
                String servletPath = request.getServletPath();
                if(servletPath.endsWith("/") == false)
                {
                    servletPath += "/";
                }

                int indexOf = constructedPath.indexOf(servletPath);
                if (indexOf >= 0)
                {
                    constructedPath = constructedPath.substring(indexOf + servletPath.length());
                }
            }

            int caAlias_end_index = constructedPath.indexOf('/');
            String caAlias = (caAlias_end_index == -1) ?
                    constructedPath : constructedPath.substring(0, caAlias_end_index);

            String caName = caManager.getCaName(caAlias);
            if(caName == null)
            {
                caName = caAlias;
            }

            X509CACmpResponder responder = caManager.getX509CACmpResponder(caName);
            if(responder == null || responder.isCAInService() == false)
            {
                if(responder == null)
                {
                    auditMessage = "Unknown CA " + caName;
                    LOG.warn(auditMessage);
                }
                else
                {
                    auditMessage = "CA " + caName + " is out of service";
                    LOG.warn(auditMessage);
                }

                response.setContentLength(0);
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);

                auditStatus = AuditStatus.FAILED;
                return;
            }

            if(auditEvent != null)
            {
                auditEvent.addEventData(new AuditEventData("CA", responder.getCA().getCAInfo().getName()));
            }

            PKIMessage pkiReq = generatePKIMessage(request.getInputStream());

            PKIHeader reqHeader = pkiReq.getHeader();
            ASN1OctetString tid = reqHeader.getTransactionID();

            PKIHeaderBuilder respHeader = new PKIHeaderBuilder(reqHeader.getPvno().getValue().intValue(),
                    reqHeader.getRecipient(), reqHeader.getSender());
            respHeader.setTransactionID(tid);

            PKIMessage pkiResp = responder.processPKIMessage(pkiReq, clientCert, auditEvent);
            byte[] pkiRespBytes = pkiResp.getEncoded("DER");

            response.setContentType(Rfc6712Servlet.CT_RESPONSE);
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentLength(pkiRespBytes.length);
            response.getOutputStream().write(pkiRespBytes);

        }catch(Throwable t)
        {
            final String message = "Throwable thrown, this should not happen!";
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

                    auditEvent.addEventData(new AuditEventData("duration",
                            System.currentTimeMillis() - auditEvent.getTimestamp().getTime()));

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

    protected PKIMessage generatePKIMessage(InputStream is)
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
            }catch(IOException e){}
        }
    }

    public void setCaManager(CAManager caManager)
    {
        this.caManager = caManager;
    }

    public void setAuditServiceRegister(AuditLoggingServiceRegister auditServiceRegister)
    {
        this.auditServiceRegister = auditServiceRegister;
    }

}
