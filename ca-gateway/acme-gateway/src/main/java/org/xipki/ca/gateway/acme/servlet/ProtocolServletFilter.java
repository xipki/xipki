// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.acme.AcmeProxyConf;
import org.xipki.ca.gateway.acme.AcmeResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * ACME Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class ProtocolServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(ProtocolServletFilter.class);

  private static final String DFLT_CFG = "etc/acme-gateway.json";

  private HttpAcmeServlet servlet;

  private ProtocolProxyConfWrapper conf;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    LOG.info("XiPKI ACME Gateway version {}", StringUtil.getVersion(getClass()));
    XipkiBaseDir.init();

    AcmeProxyConf conf0;
    try {
      conf0 = AcmeProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse configuration file " + DFLT_CFG, ex);
    }

    try {
      conf = new ProtocolProxyConfWrapper(conf0);

      AcmeResponder responder = new AcmeResponder(
          conf.getSdkClient(), conf.getSecurities().getSecurityFactory(), conf.getPopControl(), conf0.getAcme());
      responder.start();

      servlet = new HttpAcmeServlet();
      servlet.setLogReqResp(conf.isLogReqResp());
      servlet.setResponder(responder);
    } catch (InvalidConfException | ObjectCreationException e) {
      String msg = "error initializing ServletFilter";
      LOG.error(msg, e);
      throw new ServletException(msg);
    }
  } // method init

  @Override
  public void destroy() {
    if (conf != null) {
      conf.destroy();
    }

    servlet.getResponder().close();
  } // method destroy

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    servlet.service(request, response);
  } // method doFilter

}
