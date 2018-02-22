/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ocsp.server.servlet;

import java.io.EOFException;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.ocsp.api.OcspServer;
import org.xipki.ocsp.api.ResponderAndPath;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HealthCheckServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HealthCheckServlet.class);

  private static final long serialVersionUID = 1L;

  private static final String CT_RESPONSE = "application/json";

  private OcspServer server;

  public HealthCheckServlet() {
  }

  public void setServer(final OcspServer server) {
    this.server = server;
  }

  @Override
  protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
      throws ServletException, IOException {
    resp.setHeader("Access-Control-Allow-Origin", "*");
    try {
      if (server == null) {
        LOG.error("server in servlet not configured");
        resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        resp.setContentLength(0);
        return;
      }

      String path = StringUtil.getRelativeRequestUri(req.getServletPath(), req.getRequestURI());

      ResponderAndPath responderAndPath = server.getResponderForPath(path);
      if (responderAndPath == null) {
        resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
        resp.setContentLength(0);
        return;
      }

      HealthCheckResult healthResult = server.healthCheck(responderAndPath.responder());
      int status = healthResult.isHealthy()
          ? HttpServletResponse.SC_OK : HttpServletResponse.SC_INTERNAL_SERVER_ERROR;

      byte[] respBytes = healthResult.toJsonMessage(true).getBytes();
      resp.setStatus(status);
      resp.setContentType(HealthCheckServlet.CT_RESPONSE);
      resp.setContentLength(respBytes.length);
      resp.getOutputStream().write(respBytes);
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        LogUtil.warn(LOG, th, "connection reset by peer");
      } else {
        LOG.error("Throwable thrown, this should not happen", th);
      }
      resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      resp.setContentLength(0);
    } finally {
      resp.flushBuffer();
    }
  } // method doGet

}
