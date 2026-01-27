// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.dummyservlet.ctlog;

import jakarta.servlet.FilterConfig;
import org.xipki.servlet.ServletFilter;
import org.xipki.util.extra.http.XiHttpFilter;

/**
 * HTTP servlet of CT Log server.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLogServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig)
      throws Exception {
    return new CtlogHttpFilter();
  }

}
