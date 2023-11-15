// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet3;

import org.xipki.ca.gateway.cmp.servlet.CmpHttpFilter;
import org.xipki.servlet3.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

import javax.servlet.FilterConfig;

/**
 * CMP Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws Exception {
    return new CmpHttpFilter();
  }

}
