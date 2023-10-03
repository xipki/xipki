// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet3;

import org.xipki.ca.gateway.cmp.BaseCmpResponder;
import org.xipki.ca.gateway.cmp.servlet.HttpCmpServlet0;
import org.xipki.servlet3.HttpRequestMetadataRetrieverImpl;
import org.xipki.servlet3.ServletHelper;
import org.xipki.util.http.RestResponse;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    String certprofile = req.getHeader(BaseCmpResponder.HTTP_HEADER_certprofile);
    String groupEnroll = req.getHeader(BaseCmpResponder.HTTP_HEADER_groupenroll);

    Map<String, String> reqHeaders = null;
    if (certprofile != null || groupEnroll != null) {
      reqHeaders = new HashMap<>(3);
      if (certprofile != null) {
        reqHeaders.put(BaseCmpResponder.HTTP_HEADER_certprofile, certprofile);
      }
      if (groupEnroll != null) {
        reqHeaders.put(BaseCmpResponder.HTTP_HEADER_groupenroll, groupEnroll);
      }
    }

    RestResponse restResp = underlying.doPost(new HttpRequestMetadataRetrieverImpl(req),
        req.getInputStream(), reqHeaders);
    ServletHelper.fillResponse(restResp, resp);
  }

}
