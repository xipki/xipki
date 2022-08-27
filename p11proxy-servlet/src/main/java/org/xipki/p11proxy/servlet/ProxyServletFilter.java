/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.p11proxy.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.Securities;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The Servlet Filter of P11Proxy servlets.
 *
 * @author Lijun Liao
 */

public class ProxyServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(ProxyServletFilter.class);

  private static final String DFLT_SERVER_CFG = "etc/p11proxy/p11proxy.json";

  private Securities securities;

  private HttpProxyServlet servlet;

  private boolean logReqResp;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    XipkiBaseDir.init();

    P11ProxyConf conf;
    try {
      conf = P11ProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_SERVER_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse PKCS#11 Proxy configuration file " + DFLT_SERVER_CFG, ex);
    }

    String str = filterConfig.getInitParameter("logReqResp");
    logReqResp = Boolean.parseBoolean(str);
    LOG.info("logReqResp: {}", logReqResp);

    securities = new Securities();
    try {
      securities.init(conf.getSecurity());
    } catch (IOException | InvalidConfException ex) {
      LogUtil.error(LOG, ex, "could not initialize Securities");
      return;
    }

    LocalP11CryptServicePool pool = new LocalP11CryptServicePool();
    pool.setP11CryptServiceFactory(securities.getP11CryptServiceFactory());
    try {
      pool.init();
    } catch (P11TokenException | XiSecurityException ex) {
      throw new ServletException("could not initialize LocalP11CryptServicePool: " + ex.getMessage(), ex);
    }

    servlet = new HttpProxyServlet();
    servlet.setLogReqResp(logReqResp);
    servlet.setLocalP11CryptServicePool(pool);
  } // method init

  @Override
  public void destroy() {
    if (securities != null) {
      securities.close();
    }
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse resp = (HttpServletResponse) response;
    servlet.doPost(req, resp);
  } // method doFilter

}
