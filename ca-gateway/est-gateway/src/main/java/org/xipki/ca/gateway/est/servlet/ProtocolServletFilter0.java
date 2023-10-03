// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.est.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.est.EstProxyConf;
import org.xipki.ca.gateway.est.EstResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ServletException0;

import java.io.IOException;

/**
 * EST Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class ProtocolServletFilter0 {

  private static final Logger LOG = LoggerFactory.getLogger(ProtocolServletFilter0.class);

  private static final String DFLT_CFG = "etc/est-gateway.json";

  private HttpEstServlet0 servlet;

  private ProtocolProxyConfWrapper conf;

  public ProtocolServletFilter0() throws ServletException0 {
    try {
      XipkiBaseDir.init();

      EstProxyConf conf0;
      try {
        conf0 = EstProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
      } catch (IOException | InvalidConfException ex) {
        throw new IllegalArgumentException("could not parse configuration file " + DFLT_CFG, ex);
      }

      conf = new ProtocolProxyConfWrapper(conf0);

      EstResponder responder = new EstResponder(conf.getSdkClient(), conf.getSecurities().getSecurityFactory(),
          conf.getAuthenticator(), conf.getPopControl(), conf.getCaProfiles());

      servlet = new HttpEstServlet0();
      servlet.setLogReqResp(conf.isLogReqResp());
      servlet.setResponder(responder);

      GatewayUtil.auditLogPciEvent("EST-Gateway", true, "START");
    } catch (Exception e) {
      String msg = "error initializing ServletFilter";
      LOG.error(msg, e);
      GatewayUtil.auditLogPciEvent("EST-Gateway", false, "START");
      throw new ServletException0(msg);
    }
  }

  public void destroy() {
    try {
      if (conf != null) {
        conf.destroy();
        conf = null;
      }
      GatewayUtil.auditLogPciEvent("EST-Gateway", true, "SHUTDOWN");
    } catch (Exception e) {
      //LOG.error("error closing audit service", e);
    }
  }

  public HttpEstServlet0 getServlet() {
    return servlet;
  }
}
