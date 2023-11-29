// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.server.OcspRespWithCacheInfo;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.ocsp.server.ResponderAndPath;
import org.xipki.security.HashAlgo;
import org.xipki.util.*;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.EOFException;
import java.io.IOException;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

/**
 * HTTP servlet of the OCSP responder.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

class HttpOcspServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpOcspServlet.class);

  private static final long DFLT_CACHE_MAX_AGE = 60; // 1 minute

  private static final String CT_REQUEST = "application/ocsp-request";

  private static final String CT_RESPONSE = "application/ocsp-response";

  private final boolean logReqResp;

  private final OcspServer server;

  public HttpOcspServlet(boolean logReqResp, OcspServer server) {
    this.logReqResp = logReqResp;
    this.server = Args.notNull(server, "server");
  }

  public void service(XiHttpRequest req, XiHttpResponse resp) throws IOException {
    String method = req.getMethod();
    if ("GET".equalsIgnoreCase(method)) {
      doGet(req).fillResponse(resp);
    } else if ("POST".equalsIgnoreCase(method)) {
      doPost(req).fillResponse(resp);
    } else {
      resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
    }
  }

  /**
   * The reqStream is closed after this method returns.
   * @param req the request wrapper.
   * @return response
   */
  private HttpResponse doPost(XiHttpRequest req) {
    try {
      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
      ResponderAndPath responderAndPath = server.getResponderForPath(path);
      if (responderAndPath == null) {
        return new HttpResponse(HttpStatusCode.SC_NOT_FOUND);
      }

      // accept only "application/ocsp-request" as content type
      String reqContentType = req.getHeader("Content-Type");
      if (!CT_REQUEST.equalsIgnoreCase(reqContentType)) {
        return new HttpResponse(HttpStatusCode.SC_UNSUPPORTED_MEDIA_TYPE);
      }

      Responder responder = responderAndPath.getResponder();
      byte[] reqContent = IoUtil.readAllBytes(req.getInputStream());
      // request too long
      if (reqContent.length > responder.getMaxRequestSize()) {
        return new HttpResponse(HttpStatusCode.SC_REQUEST_ENTITY_TOO_LARGE);
      }

      OcspRespWithCacheInfo ocspRespWithCacheInfo = server.answer(responder, reqContent, false);
      if (ocspRespWithCacheInfo == null || ocspRespWithCacheInfo.getResponse() == null) {
        LOG.error("processRequest returned null, this should not happen");
        return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
      }

      byte[] encodedOcspResp = ocspRespWithCacheInfo.getResponse();
      if (logReqResp && LOG.isDebugEnabled()) {
        LOG.debug("HTTP POST OCSP path: {}\nRequest:\n{}\nResponse:\n{}", req.getRequestURI(),
            LogUtil.base64Encode(reqContent), LogUtil.base64Encode(encodedOcspResp));
      }

      return new HttpResponse(HttpStatusCode.SC_OK, CT_RESPONSE, null, encodedOcspResp);
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        LogUtil.warn(LOG, th, "Connection reset by peer");
      } else {
        LOG.error("Throwable thrown, this should not happen!", th);
      }

      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    }
  } // method doPosts

  private HttpResponse doGet(XiHttpRequest req) {
    String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
    ResponderAndPath responderAndPath = server.getResponderForPath(path);
    if (responderAndPath == null) {
      return new HttpResponse(HttpStatusCode.SC_NOT_FOUND);
    }

    String servletPath = responderAndPath.getServletPath();
    Responder responder = responderAndPath.getResponder();

    if (!responder.supportsHttpGet()) {
      return new HttpResponse(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
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
      return new HttpResponse(HttpStatusCode.SC_BAD_REQUEST);
    }

    try {
      // 1. RFC 2560/6960 A.1.1 specifies that request longer than 255 bytes SHOULD be sent by
      //    POST, we support GET for longer requests anyway.
      // 2. If OCSP request is sent via HTTP GET, it should be Base64-then-URL encoded, we relax
      //    this limitation by accepting also OCSP requests:
      //      - Which are Base64Url encoded, and/or
      //      - Which do not containing the Base64 padding char '='.
      if (b64OcspReq.length() > responder.getMaxRequestSize()) {
        return new HttpResponse(HttpStatusCode.SC_REQUEST_URI_TOO_LONG);
      }

      byte[] ocsReqBytes = base64Decode(StringUtil.toUtf8Bytes(b64OcspReq));
      if (ocsReqBytes == null) {
        return new HttpResponse(HttpStatusCode.SC_BAD_REQUEST);
      }

      OcspRespWithCacheInfo ocspRespWithCacheInfo = server.answer(responder, ocsReqBytes, true);
      if (ocspRespWithCacheInfo == null || ocspRespWithCacheInfo.getResponse() == null) {
        LOG.error("processRequest returned null, this should not happen");
        return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
      }

      byte[] encodedOcspResp = ocspRespWithCacheInfo.getResponse();
      if (logReqResp && LOG.isDebugEnabled()) {
        LOG.debug("HTTP GET OCSP path: {}\nResponse:\n{}", req.getRequestURI(), LogUtil.base64Encode(encodedOcspResp));
      }

      OcspRespWithCacheInfo.ResponseCacheInfo cacheInfo = ocspRespWithCacheInfo.getCacheInfo();
      Map<String, String> headers = new HashMap<>();
      if (cacheInfo != null) {
        encodedOcspResp = ocspRespWithCacheInfo.getResponse();
        long now = Clock.systemUTC().millis();

        // RFC 5019 6.2: Date: The date and time at which the OCSP server generated
        // the HTTP response.
        headers.put("Date",Long.toString(now));
        // RFC 5019 6.2: Last-Modified: date and time at which the OCSP responder
        // last modified the response.
        headers.put("Last-Modified", Long.toString(cacheInfo.getGeneratedAt()));
        // RFC 5019 6.2: Expires: This date and time will be the same as the
        // nextUpdate time-stamp in the OCSP
        // response itself.
        // This is overridden by max-age on HTTP/1.1 compatible components

        Long nextUpdate = cacheInfo.getNextUpdate();

        if (nextUpdate != null) {
          headers.put("Expires", Long.toString(nextUpdate));
        }
        // RFC 5019 6.2: This profile RECOMMENDS that the ETag value be the ASCII
        // HEX representation of the SHA1 hash of the OCSPResponse structure.
        headers.put("ETag", StringUtil.concat("\"", HashAlgo.SHA1.hexHash(encodedOcspResp), "\""));

        // Max age must be in seconds in the cache-control header
        long maxAge;
        if (responder.getCacheMaxAge() != null) {
          maxAge = responder.getCacheMaxAge();
        } else {
          maxAge = DFLT_CACHE_MAX_AGE;
        }

        if (nextUpdate != null) {
          maxAge = Math.min(maxAge, (nextUpdate - cacheInfo.getGeneratedAt()) / 1000);
        }

        headers.put("Cache-Control",
            StringUtil.concat("max-age=", Long.toString(maxAge), ",public,no-transform,must-revalidate"));
      } // end if (ocspRespWithCacheInfo)

      return new HttpResponse(HttpStatusCode.SC_OK, CT_RESPONSE, headers, encodedOcspResp);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    }
  } // method doGet

  private static byte[] base64Decode(byte[] b64OcspReqBytes) {
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

  } // method base64Decode

}
