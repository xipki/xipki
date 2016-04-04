/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.pki.ocsp.server.impl;

import java.io.EOFException;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.HealthCheckResult;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.StringUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HealthCheckServlet extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(HealthCheckServlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_RESPONSE = "application/json";

    private OcspServer server;

    public HealthCheckServlet() {
    }

    public void setServer(
            final OcspServer server) {
        this.server = server;
    }

    @Override
    protected void doGet(
            final HttpServletRequest request,
            final HttpServletResponse response)
    throws ServletException, IOException {
        response.setHeader("Access-Control-Allow-Origin", "*");
        try {
            if (server == null) {
                LOG.error("server in servlet not configured");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);
                return;
            }

            ResponderAndRelativeUri respAndUri = server.getResponderAndRelativeUri(request);
            if (respAndUri == null) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            if (StringUtil.isNotBlank(respAndUri.getRelativeUri())) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            Responder responder = respAndUri.getResponder();

            HealthCheckResult healthResult = server.healthCheck(responder);
            if (healthResult.isHealthy()) {
                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }

            response.setContentType(HealthCheckServlet.CT_RESPONSE);
            byte[] respBytes = healthResult.toJsonMessage(true).getBytes();
            response.setContentLength(respBytes.length);
            response.getOutputStream().write(respBytes);
        } catch (EOFException ex) {
            final String message = "connection reset by peer";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
            }
            LOG.debug(message, ex);

            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        } catch (Throwable th) {
            final String message = "Throwable thrown, this should not happen";
            LOG.error(LogUtil.getErrorLog(message), th.getClass().getName(), th.getMessage());
            LOG.debug(message, th);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        }

        response.flushBuffer();
    } // method doGet

}
