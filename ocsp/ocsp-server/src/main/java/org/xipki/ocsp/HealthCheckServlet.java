/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.common.HealthCheckResult;
import org.xipki.security.common.LogUtil;

/**
 * @author Lijun Liao
 */

public class HealthCheckServlet extends HttpServlet
{
    private static final Logger LOG = LoggerFactory.getLogger(HealthCheckServlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_RESPONSE = "application/json";

    private OcspResponder responder;

    public HealthCheckServlet()
    {
    }

    public void setResponder(OcspResponder responder)
    {
        this.responder = responder;
    }
    @Override
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response)
    throws ServletException, IOException
    {
        response.setHeader("Access-Control-Allow-Origin", "*");
        try
        {
            if(responder == null)
            {
                LOG.error("responder in servlet not configured");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);
                return;
            }

            HealthCheckResult healthResult = responder.healthCheck();
            if (healthResult.isHealthy())
            {
                response.setStatus(HttpServletResponse.SC_OK);
            } else
            {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }

            response.setContentType(HealthCheckServlet.CT_RESPONSE);
            byte[] respBytes = healthResult.toJsonMessage(true).getBytes();
            response.setContentLength(respBytes.length);
            response.getOutputStream().write(respBytes);
        }catch(Throwable t)
        {
            final String message = "Throwable thrown, this should not happen";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
            }
            LOG.debug(message, t);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        }

        response.flushBuffer();
    }

}
