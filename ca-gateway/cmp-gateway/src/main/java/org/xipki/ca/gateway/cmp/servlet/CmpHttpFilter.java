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
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;

/**
 * CMP Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpHttpFilter implements XiHttpFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CmpHttpFilter.class);

  private static final String DFLT_CFG = "etc/cmp-gateway.json";

  private final CmpHttpServlet servlet;

  private ProtocolProxyConfWrapper conf;

  public CmpHttpFilter() throws Exception {
    boolean succ = false;
    try {
      XipkiBaseDir.init();

      CmpProxyConf conf0;
      try {
        conf0 = CmpProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
      } catch (IOException ex) {
        throw new IOException("could not parse configuration file " + DFLT_CFG, ex);
      } catch (InvalidConfException ex) {
        throw new InvalidConfException("could not parse configuration file " + DFLT_CFG, ex);
      }

      CmpControl cmpControl = new CmpControl(conf0.getCmp());
      conf = new ProtocolProxyConfWrapper(conf0);

      CmpResponder responder = new CmpResponder(cmpControl, conf.getSdkClient(),
          conf.getSecurities().getSecurityFactory(), conf.getSigners(), conf.getAuthenticator(), conf.getPopControl());

      servlet = new CmpHttpServlet(conf.isLogReqResp(), conf0.getReverseProxyMode(), responder);
      succ = true;
    } finally {
      GatewayUtil.auditLogPciEvent(LOG, "CMP-Gateway", succ, "START");
    }
  }

  @Override
  public void destroy() {
    try {
      if (conf != null) {
        conf.destroy();
        conf = null;
      }
      GatewayUtil.auditLogPciEvent(LOG, "CMP-Gateway", true, "SHUTDOWN");
      GatewayUtil.closeAudits(LOG);
    } catch (Exception e) {
      //LOG.error("error closing audit service", e);
    }
  }

  @Override
  public void doFilter(XiHttpRequest req, XiHttpResponse resp) throws Exception {
    servlet.service(req, resp);
  }

}
