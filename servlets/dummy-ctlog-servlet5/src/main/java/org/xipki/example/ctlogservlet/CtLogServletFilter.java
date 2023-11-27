// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.example.ctlogservlet;

import jakarta.servlet.FilterConfig;
import org.xipki.example.ctlogserver.CtlogHttpFilter;
import org.xipki.servlet5.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

/**
 * HTTP servlet of CT Log server.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLogServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws Exception {
    return new CtlogHttpFilter();
  }

}