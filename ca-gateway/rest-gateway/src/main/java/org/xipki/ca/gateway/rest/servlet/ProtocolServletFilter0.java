// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.rest.RestProxyConf;
import org.xipki.ca.gateway.rest.RestResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ServletException0;

import java.io.IOException;

/**
 * REST Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class ProtocolServletFilter0 {

  private static final Logger LOG = LoggerFactory.getLogger(ProtocolServletFilter0.class);

  private static final String DFLT_CFG = "etc/rest-gateway.json";

  private HttpRestServlet0 servlet;

  private ProtocolProxyConfWrapper conf;

  public ProtocolServletFilter0() throws ServletException0 {
    try {
      XipkiBaseDir.init();

      RestProxyConf conf0;
      try {
        conf0 = RestProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
      } catch (IOException | InvalidConfException ex) {
        throw new IllegalArgumentException("could not parse configuration file " + DFLT_CFG, ex);
      }

      conf = new ProtocolProxyConfWrapper(conf0);

      RestResponder responder = new RestResponder(conf.getSdkClient(), conf.getSecurities().getSecurityFactory(),
          conf.getAuthenticator(), conf.getPopControl(), conf.getCaProfiles());

      servlet = new HttpRestServlet0();
      servlet.setLogReqResp(conf.isLogReqResp());
      servlet.setResponder(responder);

      GatewayUtil.auditLogPciEvent("REST-Gateway", true, "START");
    } catch (Exception e) {
      String msg = "error initializing ServletFilter";
      LOG.error(msg, e);
      GatewayUtil.auditLogPciEvent("REST-Gateway", false, "START");
      throw new ServletException0(msg);
    }
  }

  public void destroy() {
    try {
      if (conf != null) {
        conf.destroy();
        conf = null;
      }
      GatewayUtil.auditLogPciEvent("REST-Gateway", true, "SHUTDOWN");
    } catch (Exception e) {
      //LOG.error("error closing audit service", e);
    }
  }

  public HttpRestServlet0 getServlet() {
    return servlet;
  }
}
