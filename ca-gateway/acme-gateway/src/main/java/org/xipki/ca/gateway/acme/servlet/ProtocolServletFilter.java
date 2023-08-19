// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.servlet;

import org.xipki.ca.gateway.AbstractProtocolServletFilter;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.ca.gateway.acme.AcmeProxyConf;
import org.xipki.ca.gateway.acme.AcmeResponder;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServlet;
import java.io.IOException;

/**
 * ACME Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class ProtocolServletFilter extends AbstractProtocolServletFilter {

  private static final String DFLT_CFG = "etc/acme-gateway.json";

  private HttpAcmeServlet servlet;

  public ProtocolServletFilter() {
    super("ACME");
  }

  @Override
  protected HttpServlet getServlet() {
    return servlet;
  }

  @Override
  protected void doInit(FilterConfig filterConfig) throws ObjectCreationException, InvalidConfException {
    AcmeProxyConf conf0;
    try {
      conf0 = AcmeProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse configuration file " + DFLT_CFG, ex);
    }

    conf = new ProtocolProxyConfWrapper(conf0);

    AcmeResponder responder = new AcmeResponder(
        conf.getSdkClient(), conf.getSecurities().getSecurityFactory(), conf.getPopControl(), conf0.getAcme());
    responder.start();

    servlet = new HttpAcmeServlet();
    servlet.setLogReqResp(conf.isLogReqResp());
    servlet.setResponder(responder);
  }

  @Override
  protected void doDestroy() {
    servlet.getResponder().close();
  }

}
