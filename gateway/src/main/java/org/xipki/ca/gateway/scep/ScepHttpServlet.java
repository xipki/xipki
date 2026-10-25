// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.codec.util.IoUtil;
import org.xipki.util.http.HttpConstants;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;
import org.xipki.pkix.util.misc.LogUtil;

import java.io.IOException;

/**
 * SCEP Http Servlet.
 *
 * <p>URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.exe
 *
 * @author Lijun Liao (xipki)
 */
public class ScepHttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(ScepHttpServlet.class);

  private final boolean logReqResp;

  private final ScepResponder responder;

  public ScepHttpServlet(boolean logReqResp, ScepResponder responder) {
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

  private HttpResponse service0(XiHttpRequest req, boolean viaPost) throws IOException {
    String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);

    byte[] requestBytes = null;
    HttpResponse httpResp = null;
    try {
      requestBytes = viaPost ? IoUtil.readAllBytes(req.getInputStream())
          : Base64.decode(req.getParameter("message"));
      httpResp = responder.service(path, requestBytes, req);
      return httpResp;
    } finally {
      LogUtil.logReqResp("SCEP Gateway", LOG, logReqResp, viaPost,
          req.getRequestURI(), requestBytes, httpResp == null ? null : httpResp.body());
    }
  }

}
