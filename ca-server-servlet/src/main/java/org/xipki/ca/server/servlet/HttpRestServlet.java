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

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.ca.server.api.CmpResponderManager;
import org.xipki.ca.server.api.HttpRequestMetadataRetriever;
import org.xipki.ca.server.api.Rest;
import org.xipki.ca.server.api.RestResponse;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpRestServlet extends HttpServlet {

  private static final long serialVersionUID = 1L;

  private CmpResponderManager responderManager;

  private AuditServiceRegister auditServiceRegister;

  public HttpRestServlet() {
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
    AuditService auditService = auditServiceRegister.getAuditService();
    AuditEvent event = new AuditEvent(new Date());
    try {
      Rest rest = responderManager.getRest();

      String path = StringUtil.getRelativeRequestUri(req.getServletPath(), req.getRequestURI());
      HttpRequestMetadataRetriever httpRetriever = new HttpRequestMetadataRetrieverImpl(req);
      byte[] requestBytes = IoUtil.read(req.getInputStream());
      RestResponse response = rest.service(path, event, requestBytes, httpRetriever);

      resp.setStatus(response.statusCode());
      if (resp.getContentType() != null) {
        resp.setContentType(resp.getContentType());
      }

      for (String headerName : response.headers().keySet()) {
        resp.setHeader(headerName, response.headers().get(headerName));
      }

      byte[] respBody = response.body();
      if (respBody == null) {
        resp.setContentLength(0);
      } else {
        resp.setContentLength(respBody.length);
        resp.getOutputStream().write(respBody);
      }
    } finally {
      event.finish();
      auditService.logEvent(event);
    }
  } // method service

  public void setResponderManager(CmpResponderManager responderManager) {
    this.responderManager = responderManager;
  }

  public void setAuditServiceRegister(AuditServiceRegister auditServiceRegister) {
    this.auditServiceRegister = auditServiceRegister;
  }

}
