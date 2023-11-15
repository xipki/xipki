// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.servlet5;

import jakarta.servlet.FilterConfig;
import org.xipki.ca.server.servlet.CaHttpFilter;
import org.xipki.servlet5.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

/**
 * CA ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CaServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws Exception {
    String licenseFactoryClazz = filterConfig.getInitParameter("licenseFactory");
    return new CaHttpFilter(licenseFactoryClazz);
  }

}
