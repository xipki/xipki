// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.hsmproxy.servlet5;

import jakarta.servlet.FilterConfig;
import org.xipki.hsmproxy.HsmProxyServletFilter;
import org.xipki.servlet5.ServletFilter;
import org.xipki.util.exception.ServletException0;
import org.xipki.util.http.XiHttpFilter;

/**
 * The Servlet Filter of HSM proxy servlets.
 *
 * @author Lijun Liao (xipki)
 */

public class HsmProxyServlet5Filter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws ServletException0 {
    return new HsmProxyServletFilter();
  }

}
