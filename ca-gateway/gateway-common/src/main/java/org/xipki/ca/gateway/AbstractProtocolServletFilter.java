// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.Audits;
import org.xipki.audit.PciAuditEvent;
import org.xipki.util.StringUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * ACME Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public abstract class AbstractProtocolServletFilter implements Filter {

  private final Logger LOG = LoggerFactory.getLogger(getClass());

  protected ProtocolProxyConfWrapper conf;

  private final String name;

  public AbstractProtocolServletFilter(String name) {
    this.name = name;
  }

  protected abstract HttpServlet getServlet();

  protected abstract void doInit(FilterConfig filterConfig) throws Exception;

  protected void doDestroy() {
  }

  @Override
  public final void init(FilterConfig filterConfig) throws ServletException {
    LOG.info("XiPKI {} Gateway version {}", name, StringUtil.getVersion(getClass()));
    XipkiBaseDir.init();

    try {
      doInit(filterConfig);
      auditLogPciEvent(true, "START");
    } catch (Exception e) {
      String msg = "error initializing ServletFilter";
      LOG.error(msg, e);
      auditLogPciEvent(false, "START");
      throw new ServletException(msg);
    }
  } // method init

  @Override
  public final void destroy() {
    try {
      doDestroy();
      auditLogPciEvent(true, "SHUTDOWN");
      if (conf != null) {
        conf.destroy();
      }
    } catch (Exception e) {
      //LOG.error("error closing audit service", e);
    }
  } // method destroy

  private static void auditLogPciEvent(boolean successful, String eventType) {
    PciAuditEvent event = new PciAuditEvent();
    event.setUserId("CA-SYSTEM");
    event.setEventType(eventType);
    event.setAffectedResource("CORE");
    event.setStatus((successful ? AuditStatus.SUCCESSFUL : AuditStatus.FAILED).name());
    event.setLevel(successful ? AuditLevel.INFO : AuditLevel.ERROR);
    Audits.getAuditService().logEvent(event);
  }

  @Override
  public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    getServlet().service(request, response);
  } // method doFilter

}
