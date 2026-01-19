// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.servlet;

import jakarta.servlet.FilterConfig;
import org.xipki.ca.gateway.GatewayHttpFilter;
import org.xipki.servlet.ServletFilter;
import org.xipki.util.extra.http.XiHttpFilter;

/**
 * ACME Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class GatewayServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig)
      throws Exception {
    return new GatewayHttpFilter();
  }

}
