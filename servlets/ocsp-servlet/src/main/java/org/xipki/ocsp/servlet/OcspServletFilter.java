// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.servlet;

import jakarta.servlet.FilterConfig;
import org.xipki.ocsp.server.servlet.OcspHttpFilter;
import org.xipki.servlet.ServletFilter;
import org.xipki.util.extra.http.XiHttpFilter;

/**
 * The Servlet Filter of OCSP servlets.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig)
      throws Exception {
    return new OcspHttpFilter();
  }

}
