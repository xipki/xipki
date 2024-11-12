// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.http;

import java.io.IOException;
import java.io.OutputStream;

/**
 * HTTP response interface.
 *
 * @author Lijun Liao (xipki)
 */
public interface XiHttpResponse {

  void setStatus(int sc);

  void sendError(int sc) throws IOException;

  void setContentType(String type);

  void addHeader(String name, String value);

  void setHeader(String name, String value);

  void setContentLength(int len);

  OutputStream getOutputStream() throws IOException;

}
