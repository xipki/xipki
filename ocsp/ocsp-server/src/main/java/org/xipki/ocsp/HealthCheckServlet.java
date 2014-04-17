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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.common.HealthCheckResult;

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
            HttpServletResponse response) throws ServletException, IOException
    {
        try{
            if(responder == null)
            {
                LOG.error("responder in servlet not configured");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);
                return;
            }

            HealthCheckResult healthResult = responder.healthCheck();
            if (healthResult.isHealthy()) {
                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }

            response.setContentType(HealthCheckServlet.CT_RESPONSE);
            byte[] respBytes = healthResult.toJsonMessage(true).getBytes();
            response.setContentLength(respBytes.length);
            response.getOutputStream().write(respBytes);
        }catch(Throwable t)
        {
            LOG.error("Throwable thrown, this should not happen!", t);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        }

        response.flushBuffer();
    }

}
