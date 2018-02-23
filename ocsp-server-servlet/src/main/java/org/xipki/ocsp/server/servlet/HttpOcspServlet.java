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
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.ocsp.api.OcspRespWithCacheInfo;
import org.xipki.ocsp.api.OcspServer;
import org.xipki.ocsp.api.Responder;
import org.xipki.ocsp.api.ResponderAndPath;
import org.xipki.security.HashAlgo;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpOcspServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpOcspServlet.class);

  private static final long DFLT_CACHE_MAX_AGE = 60; // 1 minute

  private static final long serialVersionUID = 1L;

  private static final String CT_REQUEST = "application/ocsp-request";

  private static final String CT_RESPONSE = "application/ocsp-response";

  private OcspServer server;

  public HttpOcspServlet() {
  }

  public void setServer(OcspServer server) {
    this.server = ParamUtil.requireNonNull("server", server);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    try {
      String path = StringUtil.getRelativeRequestUri(req.getServletPath(),
          req.getRequestURI());
      ResponderAndPath responderAndPath = server.getResponderForPath(path);
      if (responderAndPath == null) {
        sendError(resp, HttpServletResponse.SC_NOT_FOUND);
        return;
      }

      // accept only "application/ocsp-request" as content type
      String reqContentType = req.getHeader("Content-Type");
      if (!CT_REQUEST.equalsIgnoreCase(reqContentType)) {
        sendError(resp, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
        return;
      }

      Responder responder = responderAndPath.responder();
      byte[] reqContent = IoUtil.read(req.getInputStream());
      // request too long
      if (reqContent.length > responder.maxRequestSize()) {
        sendError(resp, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        return;
      }

      OcspRespWithCacheInfo ocspRespWithCacheInfo = server.answer(responder, reqContent,
          false);
      if (ocspRespWithCacheInfo == null || ocspRespWithCacheInfo.response() == null) {
        LOG.error("processRequest returned null, this should not happen");
        sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      }

      byte[] encodedOcspResp = ocspRespWithCacheInfo.response();
      resp.setStatus(HttpServletResponse.SC_OK);
      resp.setContentType(CT_RESPONSE);
      resp.setContentLength(encodedOcspResp.length);
      resp.getOutputStream().write(encodedOcspResp);
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
  } // method servicePost

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    String path = StringUtil.getRelativeRequestUri(req.getServletPath(), req.getRequestURI());
    ResponderAndPath responderAndPath = server.getResponderForPath(path);
    if (responderAndPath == null) {
      sendError(resp, HttpServletResponse.SC_NOT_FOUND);
      return;
    }

    String servletPath = responderAndPath.servletPath();
    Responder responder = responderAndPath.responder();

    if (!responder.supportsHttpGet()) {
      sendError(resp, HttpServletResponse.SC_METHOD_NOT_ALLOWED);
      return;
    }

    String b64OcspReq;

    int offset = servletPath.length();
    // GET URI contains the request and must be much longer than 10.
    if (path.length() - offset > 10) {
      if (path.charAt(offset) == '/') {
        offset++;
      }
      b64OcspReq = path.substring(offset);
    } else {
      sendError(resp, HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    try {
      // RFC2560 A.1.1 specifies that request longer than 255 bytes SHOULD be sent by
      // POST, we support GET for longer requests anyway.
      if (b64OcspReq.length() > responder.maxRequestSize()) {
        sendError(resp, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        return;
      }

      OcspRespWithCacheInfo ocspRespWithCacheInfo = server.answer(responder,
          Base64.decode(b64OcspReq), true);
      if (ocspRespWithCacheInfo == null || ocspRespWithCacheInfo.response() == null) {
        sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return;
      }

      byte[] encodedOcspResp = ocspRespWithCacheInfo.response();

      OcspRespWithCacheInfo.ResponseCacheInfo cacheInfo = ocspRespWithCacheInfo.cacheInfo();
      if (cacheInfo != null) {
        encodedOcspResp = ocspRespWithCacheInfo.response();
        long now = System.currentTimeMillis();

        // RFC 5019 6.2: Date: The date and time at which the OCSP server generated
        // the HTTP response.
        resp.addDateHeader("Date", now);
        // RFC 5019 6.2: Last-Modified: date and time at which the OCSP responder
        // last modified the response.
        resp.addDateHeader("Last-Modified", cacheInfo.thisUpdate());
        // RFC 5019 6.2: Expires: This date and time will be the same as the
        // nextUpdate time-stamp in the OCSP
        // response itself.
        // This is overridden by max-age on HTTP/1.1 compatible components
        if (cacheInfo.nextUpdate() != null) {
          resp.addDateHeader("Expires", cacheInfo.nextUpdate());
        }
        // RFC 5019 6.2: This profile RECOMMENDS that the ETag value be the ASCII
        // HEX representation of the SHA1 hash of the OCSPResponse structure.
        resp.addHeader("ETag",
            StringUtil.concat("\\", HashAlgo.SHA1.hexHash(encodedOcspResp), "\\"));

        // Max age must be in seconds in the cache-control header
        long maxAge;
        if (responder.cacheMaxAge() != null) {
          maxAge = responder.cacheMaxAge().longValue();
        } else {
          maxAge = DFLT_CACHE_MAX_AGE;
        }

        if (cacheInfo.nextUpdate() != null) {
          maxAge = Math.min(maxAge,
              (cacheInfo.nextUpdate() - cacheInfo.thisUpdate()) / 1000);
        }

        resp.addHeader("Cache-Control",
            StringUtil.concat("max-age=", Long.toString(maxAge),
              ",public,no-transform,must-revalidate"));
      } // end if (ocspRespWithCacheInfo)

      resp.setContentLength(encodedOcspResp.length);
      resp.setContentType(CT_RESPONSE);
      resp.getOutputStream().write(encodedOcspResp);
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
  } // method serviceGet

  private static void sendError(HttpServletResponse resp, int status) {
    resp.setStatus(status);
    resp.setContentLength(0);
  }

}
