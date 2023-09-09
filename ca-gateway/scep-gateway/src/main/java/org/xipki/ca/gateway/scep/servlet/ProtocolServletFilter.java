// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep.servlet;

import org.xipki.ca.gateway.AbstractProtocolServletFilter;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.scep.CaNameScepSigners;
import org.xipki.ca.gateway.scep.ScepProxyConf;
import org.xipki.ca.gateway.scep.ScepResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServlet;
import java.io.IOException;

/**
 * SCEP Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class ProtocolServletFilter extends AbstractProtocolServletFilter {

  private static final String DFLT_CFG = "etc/scep-gateway.json";

  private HttpScepServlet servlet;

  private ProtocolProxyConfWrapper conf;

  public ProtocolServletFilter() {
    super("SCEP");
  }

  @Override
  protected HttpServlet getServlet() {
    return servlet;
  }

  @Override
  protected void doInit(FilterConfig filterConfig) throws Exception {
    ScepProxyConf conf0;
    try {
      conf0 = ScepProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse configuration file " + DFLT_CFG, ex);
    }

    conf = new ProtocolProxyConfWrapper(conf0);

    CaNameScepSigners signers = new CaNameScepSigners(conf.getSigners());
    ScepResponder responder = new ScepResponder(conf0.getScep(), conf.getSdkClient(),
        conf.getSecurities().getSecurityFactory(),  signers, conf.getAuthenticator(), conf.getPopControl());

    servlet = new HttpScepServlet();
    servlet.setLogReqResp(conf.isLogReqResp());
    servlet.setResponder(responder);
  }

}
