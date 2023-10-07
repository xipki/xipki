// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.servlet5;

import jakarta.servlet.FilterConfig;
import org.xipki.ca.gateway.acme.servlet.AcmeHttpFilter;
import org.xipki.servlet5.ServletFilter;
import org.xipki.util.exception.ServletException0;
import org.xipki.util.http.XiHttpFilter;

/**
 * ACME Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class AcmeServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws ServletException0 {
    return new AcmeHttpFilter();
  }

}
