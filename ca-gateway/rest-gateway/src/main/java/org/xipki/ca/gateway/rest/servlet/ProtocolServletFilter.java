// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest.servlet;

import org.xipki.ca.gateway.AbstractProtocolServletFilter;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.rest.RestProxyConf;
import org.xipki.ca.gateway.rest.RestResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import java.io.IOException;

/**
 * REST Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class ProtocolServletFilter extends AbstractProtocolServletFilter {

  private static final String DFLT_CFG = "etc/rest-gateway.json";

  private HttpRestServlet servlet;

  private ProtocolProxyConfWrapper conf;

  public ProtocolServletFilter() {
    super("REST");
  }

  @Override
  protected HttpServlet getServlet() {
    return servlet;
  }

  @Override
  protected void doInit(FilterConfig filterConfig) throws Exception {
    RestProxyConf conf0;
    try {
      conf0 = RestProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse configuration file " + DFLT_CFG, ex);
    }

    conf = new ProtocolProxyConfWrapper(conf0);

    RestResponder responder = new RestResponder(conf.getSdkClient(), conf.getSecurities().getSecurityFactory(),
        conf.getAuthenticator(), conf.getPopControl());

    servlet = new HttpRestServlet();
    servlet.setLogReqResp(conf.isLogReqResp());
    servlet.setResponder(responder);
  }

}
