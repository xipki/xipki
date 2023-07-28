// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.est.servlet;

import org.xipki.ca.gateway.AbstractProtocolServletFilter;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.est.EstProxyConf;
import org.xipki.ca.gateway.est.EstResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import java.io.IOException;

/**
 * EST Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class ProtocolServletFilter extends AbstractProtocolServletFilter {

  private static final String DFLT_CFG = "etc/est-gateway.json";

  private HttpEstServlet servlet;

  private ProtocolProxyConfWrapper conf;

  public ProtocolServletFilter() {
    super("EST");
  }

  @Override
  protected HttpServlet getServlet() {
    return servlet;
  }

  @Override
  protected void doInit(FilterConfig filterConfig) throws Exception {
    EstProxyConf conf0;
    try {
      conf0 = EstProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse configuration file " + DFLT_CFG, ex);
    }

    conf = new ProtocolProxyConfWrapper(conf0);

    EstResponder responder = new EstResponder(conf.getSdkClient(), conf.getSecurities().getSecurityFactory(),
        conf.getAuthenticator(), conf.getPopControl());

    servlet = new HttpEstServlet();
    servlet.setLogReqResp(conf.isLogReqResp());
    servlet.setResponder(responder);
  }

}
