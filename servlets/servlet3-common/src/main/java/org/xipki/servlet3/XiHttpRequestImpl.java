// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.servlet3;

import org.xipki.util.Args;
import org.xipki.util.http.XiHttpRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

/**
 * HTTP request wrapper.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class XiHttpRequestImpl implements XiHttpRequest {

  private final HttpServletRequest req;

  public XiHttpRequestImpl(HttpServletRequest req) {
    this.req = Args.notNull(req, "req");
  }

  @Override
  public String getHeader(String headerName) {
    return req.getHeader(headerName);
  }

  @Override
  public String getParameter(String paramName) {
    return req.getParameter(paramName);
  }

  @Override
  public String getMethod() {
    return req.getMethod();
  }

  @Override
  public String getServletPath() {
    return req.getServletPath();
  }

  @Override
  public String getContentType() {
    return req.getContentType();
  }

  @Override
  public Object getAttribute(String name) {
    return req.getAttribute(name);
  }

  @Override
  public String getRequestURI() {
    return req.getRequestURI();
  }

  @Override
  public String getContextPath() {
    return req.getContextPath();
  }

  @Override
  public X509Certificate[] getCertificateChain() {
    return (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
  }

  @Override
  public InputStream getInputStream() throws IOException {
    return req.getInputStream();
  }

  @Override
  public void setAttribute(String name, String value) {
    req.setAttribute(name, value);
  }

}
