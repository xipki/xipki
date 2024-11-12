// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.http;

/**
 * HTTP filter.
 *
 * @author Lijun Liao (xipki)
 */
public interface XiHttpFilter {

  void destroy();

  void doFilter(XiHttpRequest request, XiHttpResponse response) throws Exception;

}
