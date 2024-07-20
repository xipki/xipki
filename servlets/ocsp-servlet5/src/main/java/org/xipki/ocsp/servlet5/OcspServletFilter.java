// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.servlet5;

import jakarta.servlet.FilterConfig;
import org.xipki.ocsp.server.servlet.OcspHttpFilter;
import org.xipki.servlet5.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

/**
 * The Servlet Filter of OCSP servlets.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws Exception {
    return new OcspHttpFilter();
  }

}
