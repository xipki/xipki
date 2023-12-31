// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.example.ctlogservlet;

import org.xipki.example.ctlogserver.CtlogHttpFilter;
import org.xipki.servlet3.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

import javax.servlet.FilterConfig;

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
