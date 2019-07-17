/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ocsp.servlet;

import java.io.EOFException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.api.OcspRespWithCacheInfo;
import org.xipki.ocsp.api.OcspServer;
import org.xipki.ocsp.api.Responder;
import org.xipki.ocsp.api.ResponderAndPath;
import org.xipki.security.HashAlgo;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.Base64Url;
import org.xipki.util.Hex;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

/**
 * HTTP servlet of the OCSP responder.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class OcspServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(OcspServlet.class);

  private static final long DFLT_CACHE_MAX_AGE = 60; // 1 minute

  private static final long serialVersionUID = 1L;

  private static final String CT_REQUEST = "application/ocsp-request";

  private static final String CT_RESPONSE = "application/ocsp-response";

  private boolean logReqResp;

  private OcspServer server;

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public void setServer(OcspServer server) {
    this.server = Args.notNull(server, "server");
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    try {
      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
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

      Responder responder = responderAndPath.getResponder();
      byte[] reqContent = IoUtil.read(req.getInputStream());
      // request too long
      if (reqContent.length > responder.getMaxRequestSize()) {
        sendError(resp, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        return;
      }

      OcspRespWithCacheInfo ocspRespWithCacheInfo = server.answer(responder, reqContent, false);
      if (ocspRespWithCacheInfo == null || ocspRespWithCacheInfo.getResponse() == null) {
        LOG.error("processRequest returned null, this should not happen");
        sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      }

      byte[] encodedOcspResp = ocspRespWithCacheInfo.getResponse();
      if (logReqResp && LOG.isDebugEnabled()) {
        LOG.debug("HTTP POST OCSP path: {}\nRequest:\n{}\nResponse:\n{}", req.getRequestURI(),
            LogUtil.base64Encode(reqContent), LogUtil.base64Encode(encodedOcspResp));
      }

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
    String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
    ResponderAndPath responderAndPath = server.getResponderForPath(path);
    if (responderAndPath == null) {
      sendError(resp, HttpServletResponse.SC_NOT_FOUND);
      return;
    }

    String servletPath = responderAndPath.getServletPath();
    Responder responder = responderAndPath.getResponder();

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
      // 1. RFC 2560/6960 A.1.1 specifies that request longer than 255 bytes SHOULD be sent by
      //    POST, we support GET for longer requests anyway.
      // 2. If OCSP request is sent via HTTP GET, it should be Base64-then-URL encoded, we relax
      //    this limitation by accepting also OCSP requests:
      //      - Which are Base64Url encoded, and/or
      //      - Which do not containing the Base64 padding char '='.
      if (b64OcspReq.length() > responder.getMaxRequestSize()) {
        sendError(resp, HttpServletResponse.SC_REQUEST_URI_TOO_LONG);
        return;
      }

      byte[] ocsReqBytes = base64Decode(StringUtil.toUtf8Bytes(b64OcspReq));
      if (ocsReqBytes == null) {
        sendError(resp, HttpServletResponse.SC_BAD_REQUEST);
        return;
      }

      OcspRespWithCacheInfo ocspRespWithCacheInfo = server.answer(responder, ocsReqBytes, true);
      if (ocspRespWithCacheInfo == null || ocspRespWithCacheInfo.getResponse() == null) {
        LOG.error("processRequest returned null, this should not happen");
        sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return;
      }

      byte[] encodedOcspResp = ocspRespWithCacheInfo.getResponse();
      if (logReqResp && LOG.isDebugEnabled()) {
        LOG.debug("HTTP GET OCSP path: {}\nResponse:\n{}", req.getRequestURI(),
            LogUtil.base64Encode(encodedOcspResp));
      }

      OcspRespWithCacheInfo.ResponseCacheInfo cacheInfo = ocspRespWithCacheInfo.getCacheInfo();
      if (cacheInfo != null) {
        encodedOcspResp = ocspRespWithCacheInfo.getResponse();
        long now = System.currentTimeMillis();

        // RFC 5019 6.2: Date: The date and time at which the OCSP server generated
        // the HTTP response.
        resp.addDateHeader("Date", now);
        // RFC 5019 6.2: Last-Modified: date and time at which the OCSP responder
        // last modified the response.
        resp.addDateHeader("Last-Modified", cacheInfo.getThisUpdate());
        // RFC 5019 6.2: Expires: This date and time will be the same as the
        // nextUpdate time-stamp in the OCSP
        // response itself.
        // This is overridden by max-age on HTTP/1.1 compatible components
        if (cacheInfo.getNextUpdate() != null) {
          resp.addDateHeader("Expires", cacheInfo.getNextUpdate());
        }
        // RFC 5019 6.2: This profile RECOMMENDS that the ETag value be the ASCII
        // HEX representation of the SHA1 hash of the OCSPResponse structure.
        resp.addHeader("ETag",
            StringUtil.concat("\"", HashAlgo.SHA1.hexHash(encodedOcspResp), "\""));

        // Max age must be in seconds in the cache-control header
        long maxAge;
        if (responder.getCacheMaxAge() != null) {
          maxAge = responder.getCacheMaxAge().longValue();
        } else {
          maxAge = DFLT_CACHE_MAX_AGE;
        }

        if (cacheInfo.getNextUpdate() != null) {
          maxAge = Math.min(maxAge,
              (cacheInfo.getNextUpdate() - cacheInfo.getThisUpdate()) / 1000);
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

  private static byte[] base64Decode(byte[] b64OcspReqBytes) throws UnsupportedEncodingException {
    final int len = b64OcspReqBytes.length;
    if (Base64.containsOnlyBase64Chars(b64OcspReqBytes, 0, len)) {
      // Base64 encoded, no URL decoding is required
      return Base64.decodeFast(b64OcspReqBytes);
    } else if (Base64Url.containsOnlyBase64UrlChars(b64OcspReqBytes, 0, len)) {
      // Base64Url encoded, no URL decode is required
      return Base64Url.decodeFast(b64OcspReqBytes);
    } else {
      // Base64-then-URL encoded, URL decode required
      // count the number of encoded chars
      int cnt = 0;
      for (int i = 0; i < len - 2; i++) {
        if (b64OcspReqBytes[i] == '%') {
          cnt++;
          i += 2;
        }
      }

      if (cnt == 0) {
        return null;
      }

      byte[] realB64Bytes = new byte[len - cnt * 2];
      for (int i = 0, j = 0; j < realB64Bytes.length; i++, j++) {
        if (b64OcspReqBytes[i] == '%') {
          realB64Bytes[j] = Hex.decodeSingle(b64OcspReqBytes, i + 1);
          i += 2;
        } else {
          realB64Bytes[j] = b64OcspReqBytes[i];
        }
      }

      if (Base64.containsOnlyBase64Chars(realB64Bytes, 0, len)) {
        // Base64 encoded
        return Base64.decodeFast(realB64Bytes);
      } else if (Base64Url.containsOnlyBase64UrlChars(realB64Bytes, 0, len)) {
        // Base64Url encoded
        return Base64Url.decodeFast(realB64Bytes);
      } else {
        return null;
      }
    }

  }

}
