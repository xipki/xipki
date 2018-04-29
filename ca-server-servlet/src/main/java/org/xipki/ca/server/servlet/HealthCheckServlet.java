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

package org.xipki.ca.server.servlet;

import java.io.EOFException;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.api.ResponderManager;
import org.xipki.ca.server.api.CaCmpResponder;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HealthCheckServlet extends HttpServlet {

  private static final long serialVersionUID = 1L;

  private static final Logger LOG = LoggerFactory.getLogger(HealthCheckServlet.class);

  private static final String CT_RESPONSE = "application/json";

  public HealthCheckServlet() {
  }

  @Override
  protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
      throws ServletException, IOException {
    resp.setHeader("Access-Control-Allow-Origin", "*");

    ResponderManager responderManager = ServletHelper.getResponderManager();
    if (responderManager == null) {
      LOG.error("ServletHelper.responderManager not configured");
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      return;
    }

    try {
      String caName = null;
      CaCmpResponder responder = null;

      String path = StringUtil.getRelativeRequestUri(
          req.getServletPath(), req.getRequestURI());
      if (path.length() > 1) {
        // skip the first char which is always '/'
        String caAlias = path.substring(1);
        caName = responderManager.getCaNameForAlias(caAlias);
        if (caName == null) {
          caName = caAlias.toLowerCase();
        }
        responder = responderManager.getX509CaResponder(caName);
      }

      if (caName == null || responder == null || !responder.isOnService()) {
        String auditMessage;
        if (caName == null) {
          auditMessage = "no CA is specified";
        } else if (responder == null) {
          auditMessage = "unknown CA '" + caName + "'";
        } else {
          auditMessage = "CA '" + caName + "' is out of service";
        }
        LOG.warn(auditMessage);

        sendError(resp, HttpServletResponse.SC_NOT_FOUND);
        return;
      }

      HealthCheckResult healthResult = responder.healthCheck();
      int status = healthResult.isHealthy()
          ? HttpServletResponse.SC_OK
          : HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
      byte[] respBytes = healthResult.toJsonMessage(true).getBytes();
      resp.setStatus(status);
      resp.setContentLength(respBytes.length);
      resp.setContentType(CT_RESPONSE);
      resp.getOutputStream().write(respBytes);
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        LogUtil.warn(LOG, th, "connection reset by peer");
      } else {
        LOG.error("Throwable thrown, this should not happen!", th);
      }
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      resp.flushBuffer();
    }
  } // method service0

  private static void sendError(HttpServletResponse resp, int status) {
    resp.setStatus(status);
    resp.setContentLength(0);
  }

}
