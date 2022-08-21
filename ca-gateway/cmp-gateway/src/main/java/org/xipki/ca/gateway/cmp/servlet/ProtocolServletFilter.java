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

package org.xipki.ca.gateway.cmp.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.cmp.CmpControl;
import org.xipki.ca.gateway.cmp.CmpProxyConf;
import org.xipki.ca.gateway.cmp.CmpResponder;
import org.xipki.ca.gateway.ProtocolProxyConfWrapper;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 * CA ServletFilter.
 *
 * @author Lijun Liao
 */
public class ProtocolServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(ProtocolServletFilter.class);

  private static final String DFLT_CFG = "etc/cmp-gateway.json";

  private HttpCmpServlet servlet;

  private ProtocolProxyConfWrapper conf;

  @Override
  public void init(FilterConfig filterConfig)
      throws ServletException {
    LOG.info("XiPKI CMP Gateway version {}", StringUtil.getVersion(getClass()));
    XipkiBaseDir.init();

    CmpProxyConf conf0;
    try {
      conf0 = CmpProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException("could not parse configuration file " + DFLT_CFG, ex);
    }

    try {
      CmpControl cmpControl = new CmpControl(conf0.getCmp());
      conf = new ProtocolProxyConfWrapper(conf0);

      CmpResponder responder = new CmpResponder(cmpControl, conf.getSdkClient(),
          conf.getSecurities().getSecurityFactory(), conf.getSigners(), conf.getAuthenticator(), conf.getPopControl());

      servlet = new HttpCmpServlet();
      servlet.setLogReqResp(conf.isLogReqResp());
      servlet.setResponder(responder);
    } catch (InvalidConfException | NoSuchAlgorithmException | ObjectCreationException e) {
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
