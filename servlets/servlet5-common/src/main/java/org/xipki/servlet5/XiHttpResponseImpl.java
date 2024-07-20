// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.servlet5;

import jakarta.servlet.http.HttpServletResponse;
import org.xipki.util.Args;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;
import java.io.OutputStream;

/**
 * HTTP response wrapper.
 *
 * @author Lijun Liao (xipki)
 */
public class XiHttpResponseImpl implements XiHttpResponse {

  private final HttpServletResponse resp;

  public XiHttpResponseImpl(HttpServletResponse resp) {
    this.resp = Args.notNull(resp, "resp");
  }

  @Override
  public void setStatus(int sc) {
    resp.setStatus(sc);
  }

  @Override
  public void sendError(int sc) throws IOException {
    resp.sendError(sc);
  }

  @Override
  public void setContentType(String type) {
    resp.setContentType(type);
  }

  @Override
  public void addHeader(String name, String value) {
    resp.addHeader(name, value);
  }

  @Override
  public void setHeader(String name, String value) {
    resp.setHeader(name, value);
  }

  @Override
  public void setContentLength(int len) {
    resp.setContentLength(len);
  }

  @Override
  public OutputStream getOutputStream() throws IOException {
    return resp.getOutputStream();
  }
}
