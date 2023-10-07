// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp.servlet5;

import jakarta.servlet.FilterConfig;
import org.xipki.ca.gateway.cmp.servlet.CmpHttpFilter;
import org.xipki.servlet5.ServletFilter;
import org.xipki.util.exception.ServletException0;
import org.xipki.util.http.XiHttpFilter;

/**
 * CMP Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws ServletException0 {
    return new CmpHttpFilter();
  }

}
