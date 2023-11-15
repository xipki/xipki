// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest.servlet3;

import org.xipki.ca.gateway.rest.servlet.RestHttpFilter;
import org.xipki.servlet3.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

import javax.servlet.FilterConfig;

/**
 * REST Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class RestServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws Exception {
    return new RestHttpFilter();
  }

}
