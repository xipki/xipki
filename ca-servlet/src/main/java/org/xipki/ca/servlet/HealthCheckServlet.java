/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.servlet;

import java.io.EOFException;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.cmp.CmpResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.util.Args;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.HttpConstants;
import org.xipki.util.LogUtil;

import com.alibaba.fastjson.JSON;

/**
 * Health check servlet.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HealthCheckServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HealthCheckServlet.class);

  private static final String CT_RESPONSE = "application/json";

  private CaManagerImpl responderManager;

  public void setResponderManager(CaManagerImpl responderManager) {
    this.responderManager = Args.notNull(responderManager, "responderManager");
  }

  @Override
  protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
      throws ServletException, IOException {
    resp.setHeader("Access-Control-Allow-Origin", "*");

    try {
      String caName = null;
      CmpResponder responder = null;

      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
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
      byte[] respBytes = JSON.toJSONBytes(healthResult);
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
  } // method doGet

  private static void sendError(HttpServletResponse resp, int status) {
    resp.setStatus(status);
    resp.setContentLength(0);
  } // method sendError

}
