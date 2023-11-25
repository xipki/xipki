// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.SdkResponse;
import org.xipki.ca.server.SdkResponder;
import org.xipki.pki.ErrorCode;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.EncodeException;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;

/**
 * REST API exception.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

class HttpRaServlet {

  private static final Logger LOG = LoggerFactory.getLogger(HttpRaServlet.class);

  private final boolean logReqResp;

  private final SdkResponder responder;

  public HttpRaServlet(boolean logReqResp, SdkResponder responder) {
    this.logReqResp = logReqResp;
    this.responder = Args.notNull(responder, "responder");
  }

  public void service(XiHttpRequest req, XiHttpResponse resp) throws IOException {
    String method = req.getMethod();
    if ("GET".equalsIgnoreCase(method)) {
      service0(req, false).fillResponse(resp);
    } else if ("POST".equalsIgnoreCase(method)) {
      service0(req, true).fillResponse(resp);
    } else {
      resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
    }
  }

  private HttpResponse service0(XiHttpRequest req, boolean post) throws IOException {
    try {
      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
      byte[] requestBytes = post ? IoUtil.readAllBytesAndClose(req.getInputStream()) : null;

      SdkResponse response = responder.service(path, requestBytes, req);
      byte[] respBody = response == null ? null : response.encode();
      int httpStatus = HttpStatusCode.SC_OK;
      if (response instanceof ErrorResponse) {
        ErrorCode errCode = ((ErrorResponse) response).getCode();
        switch (errCode) {
          case UNAUTHORIZED:
          case NOT_PERMITTED:
            httpStatus = HttpStatusCode.SC_UNAUTHORIZED;
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
            httpStatus = HttpStatusCode.SC_BAD_REQUEST;
            break;
          case PATH_NOT_FOUND:
            httpStatus = HttpStatusCode.SC_NOT_FOUND;
            break;
          case CRL_FAILURE:
          case DATABASE_FAILURE:
          case SYSTEM_FAILURE:
          case SYSTEM_UNAVAILABLE:
          default:
            httpStatus = HttpStatusCode.SC_INTERNAL_SERVER_ERROR;
            break;
        }
      }

      if (logReqResp && LOG.isDebugEnabled()) {
        String respBodyStr = respBody == null ? null : Base64.encodeToString(respBody, true);
        LOG.debug("HTTP RA path: {}\nResponse:\n{}", req.getRequestURI(), respBodyStr);
      }

      return new HttpResponse(httpStatus, "application/cbor", null, respBody);
    } catch (EncodeException ex) {
      LOG.error("Error encoding SdkResponse", ex);
      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    } catch (RuntimeException ex) {
      LOG.error("RuntimeException thrown, this should not happen!", ex);
      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    }
  }

}
