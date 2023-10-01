// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.Audits;
import org.xipki.audit.PciAuditEvent;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.cmp.CmpControl;
import org.xipki.ca.gateway.cmp.CmpProxyConf;
import org.xipki.ca.gateway.cmp.CmpResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;

/**
 * CMP Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class ProtocolServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(ProtocolServletFilter.class);

  private static final String DFLT_CFG = "etc/cmp-gateway.json";

  private HttpCmpServlet servlet;

  private ProtocolProxyConfWrapper conf;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    try {
      XipkiBaseDir.init();

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

      auditLogPciEvent(true, "START");
    } catch (Exception e) {
      String msg = "error initializing ServletFilter";
      LOG.error(msg, e);
      auditLogPciEvent(false, "START");
      throw new ServletException(msg);
    }
  }

  @Override
  public void destroy() {
    try {
      if (conf != null) {
        conf.destroy();
        conf = null;
      }
      auditLogPciEvent(true, "SHUTDOWN");
    } catch (Exception e) {
      //LOG.error("error closing audit service", e);
    }
  }

  @Override
  public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    servlet.service(request, response);
  }

  private static void auditLogPciEvent(boolean successful, String eventType) {
    PciAuditEvent event = PciAuditEvent.newPciAuditEvent("CMP-Gateway", eventType, "CORE",
        successful ? AuditStatus.SUCCESSFUL : AuditStatus.FAILED, successful ? AuditLevel.INFO : AuditLevel.ERROR);
    Audits.getAuditService().logEvent(event);
  }

}
