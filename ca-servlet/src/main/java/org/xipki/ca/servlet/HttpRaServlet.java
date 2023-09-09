// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.SdkResponse;
import org.xipki.ca.server.SdkResponder;
import org.xipki.security.util.HttpRequestMetadataRetriever;
import org.xipki.util.Args;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.ErrorCode;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * REST API exception.
 *
 * @author Lijun Liao (xipki)
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
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    service0(req, resp, false);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    service0(req, resp, true);
  }

  private void service0(HttpServletRequest req, HttpServletResponse resp, boolean viaPost)
      throws IOException {
    try {
      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
      HttpRequestMetadataRetriever httpRetriever = new HttpRequestMetadataRetrieverImpl(req);
      byte[] requestBytes = IoUtil.readAndClose(req.getInputStream());

      SdkResponse response = responder.service(path, requestBytes, httpRetriever);
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
        String respBodyStr = respBody == null ? null : new String(respBody);
        if (viaPost) {
          LOG.debug("HTTP POST CA REST path: {}\nRequest:\n{}\nResponse:\n{}", req.getRequestURI(),
              new String(requestBytes), respBodyStr);
        } else {
          LOG.debug("HTTP GET CA REST path: {}\nResponse:\n{}", req.getRequestURI(), respBodyStr);
        }
      }

      if (respBody == null || respBody.length == 0) {
        resp.setContentLength(0);
      } else {
        resp.setContentLength(respBody.length);
        resp.getOutputStream().write(respBody);
      }
    } catch (RuntimeException ex) {
      LOG.error("RuntimeException thrown, this should not happen!", ex);
      resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  } // method service0

}
