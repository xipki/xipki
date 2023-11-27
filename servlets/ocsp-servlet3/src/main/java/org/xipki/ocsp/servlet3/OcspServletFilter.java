// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.servlet3;

import org.xipki.ocsp.server.servlet.OcspHttpFilter;
import org.xipki.servlet3.ServletFilter;
import org.xipki.util.http.XiHttpFilter;

import javax.servlet.FilterConfig;

/**
 * The Servlet Filter of OCSP servlets.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspServletFilter extends ServletFilter {

  @Override
  protected XiHttpFilter initFilter(FilterConfig filterConfig) throws Exception {
    String licenseFactoryClazz = filterConfig.getInitParameter("licenseFactory");
    return new OcspHttpFilter(licenseFactoryClazz);
  }

}
