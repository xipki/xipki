// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.xipki.util.http.XiHttpRequest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A {@link XiHttpRequest} with given method, headers, parameters and TLS client certificate.
 *
 * @author Lijun Liao (xipki)
 */
public final class TestHttpRequest implements XiHttpRequest {

  private final String method;

  private final Map<String, String> headers = new HashMap<>();

  private final Map<String, String> parameters = new HashMap<>();

  private final Map<String, Object> attributes = new HashMap<>();

  private X509Certificate[] certificateChain;

  public TestHttpRequest(String method) {
    this.method = method;
  }

  public TestHttpRequest header(String name, String value) {
    headers.put(name.toLowerCase(Locale.ROOT), value);
    return this;
  }

  public TestHttpRequest parameter(String name, String value) {
    parameters.put(name, value);
    return this;
  }

  public void setCertificateChain(X509Certificate... certificateChain) {
    this.certificateChain = certificateChain;
  }

  @Override
  public String getHeader(String headerName) {
    return headers.get(headerName.toLowerCase(Locale.ROOT));
  }

  @Override
  public String getParameter(String paramName) {
    return parameters.get(paramName);
  }

  @Override
  public String getMethod() {
    return method;
  }

  @Override
  public String getServletPath() {
    return "";
  }

  @Override
  public String getContentType() {
    return getHeader("Content-Type");
  }

  @Override
  public Object getAttribute(String name) {
    return attributes.get(name);
  }

  @Override
  public String getRequestURI() {
    return "";
  }

  @Override
  public InputStream getInputStream() {
    return new ByteArrayInputStream(new byte[0]);
  }

  @Override
  public void setAttribute(String name, String value) {
    attributes.put(name, value);
  }

  @Override
  public String getContextPath() {
    return "";
  }

  @Override
  public X509Certificate[] getCertificateChain() {
    return certificateChain;
  }

}
