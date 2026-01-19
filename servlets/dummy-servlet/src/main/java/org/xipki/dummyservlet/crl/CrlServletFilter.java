// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.dummyservlet.crl;

import jakarta.servlet.FilterConfig;
import org.xipki.servlet.ServletFilter;
import org.xipki.util.extra.http.XiHttpFilter;

/**
 * Dummy CRL ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CrlServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig)
      throws Exception {
    return new CrlHttpFilter();
  }

}
