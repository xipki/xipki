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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.*;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.SdkResponse;
import org.xipki.ca.server.SdkResponder;
import org.xipki.security.util.HttpRequestMetadataRetriever;
import org.xipki.util.Args;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.ErrorCode;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * REST API exception.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpRaServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpRaServlet.class);

  private boolean logReqResp;

  private SdkResponder responder;

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public void setResponder(SdkResponder responder) {
    this.responder = Args.notNull(responder, "responder");
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    service0(req, resp, false);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    service0(req, resp, true);
  }

  private void service0(HttpServletRequest req, HttpServletResponse resp, boolean viaPost)
      throws IOException {
    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent(new Date());
    try {
      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
      HttpRequestMetadataRetriever httpRetriever = new HttpRequestMetadataRetrieverImpl(req);
      byte[] requestBytes = IoUtil.read(req.getInputStream());

      SdkResponse response = responder.service(path, event, requestBytes, httpRetriever);
      byte[] respBody = response == null ? null : response.encode();
      int httpStatus = HttpServletResponse.SC_OK;
      if (response instanceof ErrorResponse) {
        ErrorCode errCode = ((ErrorResponse) response).getCode();
        switch (errCode) {
          case UNAUTHORIZED:
          case NOT_PERMITTED:
            httpStatus = HttpServletResponse.SC_UNAUTHORIZED;
            break;
          case BAD_CERT_TEMPLATE:
          case BAD_POP:
          case BAD_REQUEST:
          case INVALID_EXTENSION:
          case UNKNOWN_CERT_PROFILE:
          case UNKNOWN_CERT:
          case ALREADY_ISSUED:
          case CERT_REVOKED:
          case CERT_UNREVOKED:
            httpStatus = HttpServletResponse.SC_BAD_REQUEST;
            break;
          case PATH_NOT_FOUND:
            httpStatus = HttpServletResponse.SC_NOT_FOUND;
            break;
          case CRL_FAILURE:
          case DATABASE_FAILURE:
          case SYSTEM_FAILURE:
          case SYSTEM_UNAVAILABLE:
          default:
            httpStatus = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
            break;
        }
      }

      resp.setStatus(httpStatus);
      resp.setContentType("application/json");

      if (logReqResp && LOG.isDebugEnabled()) {
        if (viaPost) {
          LOG.debug("HTTP POST CA REST path: {}\nRequest:\n{}\nResponse:\n{}", req.getRequestURI(),
              new String(requestBytes), new String(respBody));
        } else {
          LOG.debug("HTTP GET CA REST path: {}\nResponse:\n{}", req.getRequestURI(), new String(respBody));
        }
      }

      if (respBody == null || respBody.length == 0) {
        resp.setContentLength(0);
      } else {
        resp.setContentLength(respBody.length);
        resp.getOutputStream().write(respBody);
      }
      if (event.getStatus() == null) {
        event.setStatus(AuditStatus.SUCCESSFUL);
      }
    } catch (RuntimeException ex) {
      event.setStatus(AuditStatus.FAILED);
      event.setLevel(AuditLevel.ERROR);
      LOG.error("RuntimeException thrown, this should not happen!", ex);
      resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      event.finish();
      auditService.logEvent(event);
    }
  } // method service0

}
