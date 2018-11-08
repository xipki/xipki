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

package org.xipki.ca.servlet;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.Audits;
import org.xipki.ca.server.api.HttpRequestMetadataRetriever;
import org.xipki.ca.server.api.ResponderManager;
import org.xipki.ca.server.api.RestResponder;
import org.xipki.ca.server.api.RestResponse;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

@SuppressWarnings("serial")
public class HttpRestServlet extends HttpServlet {

  private static Logger LOG = LoggerFactory.getLogger(HttpRestServlet.class);

  private ResponderManager responderManager;

  public void setResponderManager(ResponderManager responderManager) {
    this.responderManager =
        ParamUtil.requireNonNull("responderManager", responderManager);;
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
      RestResponder rest = responderManager.getRestResponder();

      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
      HttpRequestMetadataRetriever httpRetriever = new HttpRequestMetadataRetrieverImpl(req);
      byte[] requestBytes = IoUtil.read(req.getInputStream());
      RestResponse response = rest.service(path, event, requestBytes, httpRetriever);

      resp.setStatus(response.getStatusCode());
      if (resp.getContentType() != null) {
        resp.setContentType(resp.getContentType());
      }

      Map<String, String> headers = response.getHeaders();
      if (headers != null) {
        for (String headerName : response.getHeaders().keySet()) {
          resp.setHeader(headerName, response.getHeaders().get(headerName));
        }
      }

      byte[] respBody = response.getBody();
      if (respBody == null) {
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
      throw ex;
    } finally {
      event.finish();
      auditService.logEvent(event);
    }
  } // method service

}
