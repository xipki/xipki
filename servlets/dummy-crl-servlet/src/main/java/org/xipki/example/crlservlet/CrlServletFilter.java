// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.example.crlservlet;

import jakarta.servlet.FilterConfig;
import org.xipki.example.crlserver.CrlHttpFilter;
import org.xipki.servlet.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

/**
 * Dummy CRL ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CrlServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws Exception {
    return new CrlHttpFilter();
  }

}
