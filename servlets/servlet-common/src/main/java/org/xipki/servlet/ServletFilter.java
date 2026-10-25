// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.servlet;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.util.Args;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;

/**
 * Servlet Filter.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class ServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(ServletFilter.class);

  private XiHttpFilter filter0;

  protected abstract XiHttpFilter initFilter(FilterConfig filterConfig) throws Exception;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    try {
      filter0 = initFilter(filterConfig);
    } catch (Exception ex) {
      LOG.error("error initializing ServletFiler", ex);
      throw new ServletException(ex);
    }
  }

  @Override
  public void destroy() {
    if (filter0 != null) {
      filter0.destroy();
      filter0 = null;
    }
  }

  @Override
  public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (filter0 == null) {
      throw new ServletException("filter is not initialized");
    }

    if (!(request instanceof HttpServletRequest && response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    try {
      filter0.doFilter(new XiHttpRequestImpl((HttpServletRequest) request),
          new XiHttpResponseImpl((HttpServletResponse) response));
    } catch (IOException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ServletException(ex);
    }
  }

  /**
   * Xi Http Request Impl.
   * @author Lijun Liao (xipki)
   */
  private static class XiHttpRequestImpl implements XiHttpRequest {

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

  /**
   * Xi Http Response Impl.
   *
   * @author Lijun Liao (xipki)
   */
  private static class XiHttpResponseImpl implements XiHttpResponse {

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

}
