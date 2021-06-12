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

package org.xipki.p11proxy.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.EOFException;
import java.io.IOException;

/**
 * HTTP proxy servlet.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpProxyServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpProxyServlet.class);

  private static final String REQUEST_MIMETYPE = "application/x-xipki-pkcs11";

  private static final String RESPONSE_MIMETYPE = "application/x-xipki-pkcs11";

  private final P11ProxyResponder responder;

  private LocalP11CryptServicePool localP11CryptServicePool;

  private boolean logReqResp;

  public HttpProxyServlet() {
    responder = new P11ProxyResponder();
  }

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    try {
      // accept only "application/ocsp-request" as content type
      String reqContentType = req.getHeader("Content-Type");
      if (!REQUEST_MIMETYPE.equalsIgnoreCase(reqContentType)) {
        sendError(resp, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
        return;
      }

      byte[] requestBytes = IoUtil.read(req.getInputStream());
      byte[] responseBytes = responder.processRequest(localP11CryptServicePool, requestBytes);

      if (logReqResp && LOG.isDebugEnabled()) {
        LOG.debug("HTTP POST OCSP path: {}\nRequest:\n{}\nResponse:\n{}", req.getRequestURI(),
            LogUtil.base64Encode(requestBytes), LogUtil.base64Encode(responseBytes));
      }

      resp.setStatus(HttpServletResponse.SC_OK);
      resp.setContentType(RESPONSE_MIMETYPE);
      resp.setContentLength(responseBytes.length);
      resp.getOutputStream().write(responseBytes);
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        LogUtil.warn(LOG, th, "Connection reset by peer");
      } else {
        LOG.error("Throwable thrown, this should not happen!", th);
      }

      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      resp.flushBuffer();
    }
  } // method doPost

  public void setLocalP11CryptServicePool(LocalP11CryptServicePool localP11CryptServicePool) {
    this.localP11CryptServicePool = localP11CryptServicePool;
  }

  private static void sendError(HttpServletResponse resp, int status) {
    resp.setStatus(status);
    resp.setContentLength(0);
  }

}
