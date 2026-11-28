// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.servlet;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.util.http.HttpConstants;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The CA management servlet {@link CaHttpMgmtServlet} in a JDK HTTP server on the loopback
 * address, for the tests of the management client. TLS is simulated: every request is treated
 * as sent with the given TLS client certificate.
 *
 * @author Lijun Liao (xipki)
 */
public final class CaMgmtTestServer implements AutoCloseable {

  private static final String CONTEXT = "/mgmt";

  private final HttpServer server;

  private final CaHttpMgmtServlet servlet;

  private volatile X509Certificate clientCert;

  /**
   * Creates and starts the server.
   *
   * @param caManager the CA manager.
   * @param mgmtCert the certificate of the management client permitted by the servlet.
   * @param clientCert the TLS client certificate of the requests.
   * @throws IOException if the server could not be started.
   * @throws CertificateException if a certificate could not be converted.
   */
  public CaMgmtTestServer(CaManager caManager, X509Cert mgmtCert, X509Cert clientCert)
      throws IOException, CertificateException {
    this.servlet = new CaHttpMgmtServlet(caManager, null, List.of(mgmtCert), false);
    setClientCert(clientCert);
    this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(CONTEXT, this::serve);
    server.start();
  }

  /** The URL of the management servlet, to be used as server URL of the client. */
  public String url() {
    return "http://127.0.0.1:" + server.getAddress().getPort() + CONTEXT + "/";
  }

  /** Sets the TLS client certificate of the following requests, {@code null} for none. */
  public void setClientCert(X509Cert cert) throws CertificateException {
    this.clientCert = (cert == null) ? null
        : (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
  }

  @Override
  public void close() {
    server.stop(0);
  }

  private void serve(HttpExchange exchange) throws IOException {
    try {
      String path = exchange.getRequestURI().getPath().substring(CONTEXT.length());
      Request request = new Request(exchange, clientCert);
      request.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path);
      Response response = new Response();
      servlet.service(request, response);

      for (Map.Entry<String, String> h : response.headers.entrySet()) {
        exchange.getResponseHeaders().set(h.getKey(), h.getValue());
      }
      byte[] body = response.body.toByteArray();
      exchange.sendResponseHeaders(response.status, body.length == 0 ? -1 : body.length);
      if (body.length > 0) {
        try (OutputStream out = exchange.getResponseBody()) {
          out.write(body);
        }
      }
    } finally {
      exchange.close();
    }
  }

  private static final class Request implements XiHttpRequest {

    private final HttpExchange exchange;

    private final X509Certificate clientCert;

    private final Map<String, Object> attributes = new HashMap<>();

    Request(HttpExchange exchange, X509Certificate clientCert) {
      this.exchange = exchange;
      this.clientCert = clientCert;
    }

    @Override
    public String getHeader(String headerName) {
      return exchange.getRequestHeaders().getFirst(headerName);
    }

    @Override
    public String getParameter(String paramName) {
      return null;
    }

    @Override
    public String getMethod() {
      return exchange.getRequestMethod();
    }

    @Override
    public String getServletPath() {
      return CONTEXT;
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
      return exchange.getRequestURI().getPath();
    }

    @Override
    public InputStream getInputStream() {
      return exchange.getRequestBody();
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
      return clientCert == null ? null : new X509Certificate[]{clientCert};
    }

  }

  private static final class Response implements XiHttpResponse {

    private int status = 200;

    private final Map<String, String> headers = new LinkedHashMap<>();

    private final ByteArrayOutputStream body = new ByteArrayOutputStream();

    @Override
    public void setStatus(int sc) {
      this.status = sc;
    }

    @Override
    public void sendError(int sc) {
      this.status = sc;
    }

    @Override
    public void setContentType(String type) {
      headers.put("Content-Type", type);
    }

    @Override
    public void addHeader(String name, String value) {
      headers.put(name, value);
    }

    @Override
    public void setHeader(String name, String value) {
      headers.put(name, value);
    }

    @Override
    public void setContentLength(int len) {
    }

    @Override
    public OutputStream getOutputStream() {
      return body;
    }

  }

}
