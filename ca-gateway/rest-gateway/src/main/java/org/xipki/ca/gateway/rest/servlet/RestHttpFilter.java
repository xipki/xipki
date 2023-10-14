// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.Audits;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.rest.RestProxyConf;
import org.xipki.ca.gateway.rest.RestResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ServletException0;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;

/**
 * REST Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class RestHttpFilter implements XiHttpFilter {

  private static final Logger LOG = LoggerFactory.getLogger(RestHttpFilter.class);

  private static final String DFLT_CFG = "etc/rest-gateway.json";

  private RestHttpServlet servlet;

  private ProtocolProxyConfWrapper conf;

  public RestHttpFilter() throws ServletException0 {
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

      servlet = new RestHttpServlet();
      servlet.setLogReqResp(conf.isLogReqResp());
      servlet.setResponder(responder);

      GatewayUtil.auditLogPciEvent(LOG, "REST-Gateway", true, "START");
    } catch (Exception e) {
      String msg = "error initializing ServletFilter";
      LOG.error(msg, e);
      GatewayUtil.auditLogPciEvent(LOG, "REST-Gateway", false, "START");
      throw new ServletException0(msg);
    }
  }

  @Override
  public void destroy() {
    try {
      if (conf != null) {
        conf.destroy();
        conf = null;
      }

      GatewayUtil.auditLogPciEvent(LOG, "REST-Gateway", true, "SHUTDOWN");
      GatewayUtil.closeAudits(LOG);
    } catch (Exception e) {
      //LOG.error("error closing audit service", e);
    }
  }

  @Override
  public void doFilter(XiHttpRequest req, XiHttpResponse resp) throws IOException {
    servlet.service(req, resp);
  }

}
