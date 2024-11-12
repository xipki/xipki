// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.servlet;

import jakarta.servlet.FilterConfig;
import org.xipki.ca.server.servlet.CaHttpFilter;
import org.xipki.servlet.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

/**
 * CA ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CaServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws Exception {
    return new CaHttpFilter();
  }

}
