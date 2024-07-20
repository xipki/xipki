// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.servlet5;

import jakarta.servlet.http.HttpServletRequest;
import org.xipki.util.http.XiHttpRequest;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

/**
 * HTTP request wrapper.
 * @author Lijun Liao
 */

public class XiHttpRequestImpl implements XiHttpRequest {

  private final HttpServletRequest req;

  public XiHttpRequestImpl(HttpServletRequest req) {
    this.req = req;
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
  public String getContextPath() {
    return req.getContextPath();
  }

  @Override
  public X509Certificate[] getCertificateChain() {
    return (X509Certificate[]) req.getAttribute("jakarta.servlet.request.X509Certificate");
  }

  @Override
  public String getRequestURI() {
    return req.getRequestURI();
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
