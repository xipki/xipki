// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.hsmproxy.servlet3;

import org.xipki.hsmproxy.HsmProxyServletFilter;
import org.xipki.servlet3.ServletFilter;
import org.xipki.util.exception.ServletException0;
import org.xipki.util.http.XiHttpFilter;

import javax.servlet.FilterConfig;

/**
 * The Servlet Filter of HSM proxy servlets.
 *
 * @author Lijun Liao (xipki)
 */

public class HsmProxyServlet3Filter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws ServletException0 {
    return new HsmProxyServletFilter();
  }

}
