// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet;

import org.xipki.ca.gateway.AbstractProtocolServletFilter;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.cmp.CmpControl;
import org.xipki.ca.gateway.cmp.CmpProxyConf;
import org.xipki.ca.gateway.cmp.CmpResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServlet;
import java.io.IOException;

/**
 * CMP Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class ProtocolServletFilter extends AbstractProtocolServletFilter {

  private static final String DFLT_CFG = "etc/cmp-gateway.json";

  private HttpCmpServlet servlet;

  private ProtocolProxyConfWrapper conf;

  public ProtocolServletFilter() {
    super("CMP");
  }

  @Override
  protected HttpServlet getServlet() {
    return servlet;
  }

  @Override
  protected void doInit(FilterConfig filterConfig) throws Exception {
    CmpProxyConf conf0;
    try {
      conf0 = CmpProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse configuration file " + DFLT_CFG, ex);
    }

    CmpControl cmpControl = new CmpControl(conf0.getCmp());
    conf = new ProtocolProxyConfWrapper(conf0);

    CmpResponder responder = new CmpResponder(cmpControl, conf.getSdkClient(),
        conf.getSecurities().getSecurityFactory(), conf.getSigners(), conf.getAuthenticator(), conf.getPopControl());

    servlet = new HttpCmpServlet();
    servlet.setLogReqResp(conf.isLogReqResp());
    servlet.setResponder(responder);
  }

}
