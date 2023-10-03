// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.cmp.CmpControl;
import org.xipki.ca.gateway.cmp.CmpProxyConf;
import org.xipki.ca.gateway.cmp.CmpResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ServletException0;

import java.io.IOException;

/**
 * CMP Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class ProtocolServletFilter0 {

  private static final Logger LOG = LoggerFactory.getLogger(ProtocolServletFilter0.class);

  private static final String DFLT_CFG = "etc/cmp-gateway.json";

  private HttpCmpServlet0 servlet;

  private ProtocolProxyConfWrapper conf;

  public ProtocolServletFilter0() throws ServletException0 {
    try {
      XipkiBaseDir.init();

      CmpProxyConf conf0;
      try {
        conf0 = CmpProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
      } catch (IOException | InvalidConfException ex) {
        throw new ServletException0("could not parse configuration file " + DFLT_CFG, ex);
      }

      CmpControl cmpControl = new CmpControl(conf0.getCmp());
      conf = new ProtocolProxyConfWrapper(conf0);

      CmpResponder responder = new CmpResponder(cmpControl, conf.getSdkClient(),
          conf.getSecurities().getSecurityFactory(), conf.getSigners(), conf.getAuthenticator(), conf.getPopControl());

      servlet = new HttpCmpServlet0();
      servlet.setLogReqResp(conf.isLogReqResp());
      servlet.setResponder(responder);

      GatewayUtil.auditLogPciEvent("CMP-Gateway", true, "START");
    } catch (Exception e) {
      String msg = "error initializing ServletFilter";
      LOG.error(msg, e);
      GatewayUtil.auditLogPciEvent("CMP-Gateway", false, "START");
      throw new ServletException0(msg);
    }
  }

  public void destroy() {
    try {
      if (conf != null) {
        conf.destroy();
        conf = null;
      }
      GatewayUtil.auditLogPciEvent("CMP-Gateway", true, "SHUTDOWN");
    } catch (Exception e) {
      //LOG.error("error closing audit service", e);
    }
  }

  public HttpCmpServlet0 getServlet() {
    return servlet;
  }
}
