// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet5;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.xipki.ca.gateway.cmp.BaseCmpResponder;
import org.xipki.ca.gateway.cmp.servlet.HttpCmpServlet0;
import org.xipki.servlet5.HttpRequestMetadataRetrieverImpl;
import org.xipki.servlet5.ServletHelper;
import org.xipki.util.http.RestResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * CMP servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class HttpCmpServlet extends HttpServlet {

  private HttpCmpServlet0 underlying;

  public void setUnderlying(HttpCmpServlet0 underlying) {
    this.underlying = underlying;
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String[] headerNames = {BaseCmpResponder.HTTP_HEADER_certprofile, BaseCmpResponder.HTTP_HEADER_groupenroll};
    Map<String, String> reqHeaders = null;
    for (String headerName : headerNames) {
      String value = req.getHeader(headerName);
      if (value != null) {
        if (reqHeaders == null) {
          reqHeaders = new HashMap<>(3);
        }
        reqHeaders.put(headerName, value);
      }
    }

    RestResponse restResp = underlying.doPost(new HttpRequestMetadataRetrieverImpl(req),
        req.getInputStream(), reqHeaders);
    ServletHelper.fillResponse(restResp, resp);
  }

}
