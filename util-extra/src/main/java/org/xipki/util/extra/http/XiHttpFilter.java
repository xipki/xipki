// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.extra.http;

/**
 * HTTP filter.
 *
 * @author Lijun Liao (xipki)
 */
public interface XiHttpFilter {

  void destroy();

  void doFilter(XiHttpRequest request, XiHttpResponse response)
      throws Exception;

}
