// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.servlet3;

import org.xipki.ca.server.servlet.CaHttpFilter;
import org.xipki.servlet3.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

import javax.servlet.FilterConfig;

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
