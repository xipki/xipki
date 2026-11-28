// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.servlet;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.ocsp.OCSPResponse;
import org.xipki.asn1.ocsp.OCSPResponseStatus;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.test.OcspTestUtil;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.http.HttpConstants;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;
import org.xipki.util.misc.NameId;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The HTTP interface of the OCSP server ({@link HttpOcspServlet}): GET with the different
 * encodings of the request, POST, the caching headers of RFC 5019 and the HTTP errors.
 *
 * @author Lijun Liao (xipki)
 */
public class HttpOcspServletH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static CaH2TestEnv env;

  private static OcspServer server;

  private static HttpOcspServlet servlet;

  private static X509Cert caCert;

  private static BigInteger serial;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv(true);
    CaManagerImpl caManager = env.caManager();
    caCert = env.caCert();
    caManager.addPublisher(new PublisherEntry(new NameId(null, "ocsp-publisher"), "ocsp",
        "datasource=ocsp,publish.goodcerts=true"));
    caManager.addPublisherToCa("ocsp-publisher", CA);
    serial = X509Util.parseCert(caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=servlet.example.org,O=myorg,C=DE", null, null).cert()).serialNumber();

    server = new OcspServer(env.workDir().toString());
    server.setSecurityFactory(env.securities().securityFactory());
    server.setConfFile(OcspTestUtil.writeResponderConf(env.workDir(), env.ocspDbConf(),
        "{\"datasource\": \"ocspdb\", \"type\": \"xipki-db\", \"conf\": {}}", "unknown", "")
        .toString());
    server.init(true);
    servlet = new HttpOcspServlet(false, server);
  }

  @AfterClass
  public static void shutdown() {
    if (server != null) {
      server.close();
    }
    if (env != null) {
      env.close();
    }
  }

  // ---------------------------------------------------------------- GET

  @Test
  public void getWithBase64() throws Exception {
    Resp resp = get("/" + Base64.encodeToString(request()));
    assertSuccessful(resp);
  }

  @Test
  public void getWithBase64ThenUrlEncoded() throws Exception {
    String b64 = Base64.encodeToString(request());
    // the first char is always escaped: whether the Base64 text contains '+', '/' or '='
    // depends on the (random) serial number
    String urlEncoded = escape(b64.charAt(0))
        + URLEncoder.encode(b64.substring(1), StandardCharsets.US_ASCII);
    assertSuccessful(get("/" + urlEncoded));
  }

  @Test
  public void getWithBase64Url() throws Exception {
    String b64url = Base64.encodeToString(request()).replace('+', '-').replace('/', '_');
    assertSuccessful(get("/" + b64url));
    // without padding
    assertSuccessful(get("/" + b64url.replace("=", "")));
  }

  @Test
  public void getHasCachingHeaders() throws Exception {
    Resp resp = get("/" + Base64.encodeToString(request()));
    assertSuccessful(resp);

    // RFC 5019 6.2
    Assert.assertEquals("\"" + HashAlgo.SHA1.hexHash(resp.body) + "\"", resp.header("ETag"));
    Assert.assertNotNull("Date", resp.header("Date"));
    Assert.assertNotNull("Last-Modified", resp.header("Last-Modified"));
    String cacheControl = resp.header("Cache-Control");
    Assert.assertNotNull("Cache-Control", cacheControl);
    Assert.assertTrue(cacheControl, cacheControl.startsWith("max-age="));
    long maxAge = Long.parseLong(cacheControl.substring("max-age=".length(),
        cacheControl.indexOf(',')));
    Assert.assertTrue("max-age " + maxAge, maxAge >= 0 && maxAge <= 60);

    String expires = resp.header("Expires");
    if (expires != null) {
      // nextUpdate of the response: not before the response was generated
      Instant date = Instant.from(DateTimeFormatter.RFC_1123_DATE_TIME.parse(resp.header("Date")));
      Instant expiresAt = Instant.from(DateTimeFormatter.RFC_1123_DATE_TIME.parse(expires));
      Assert.assertFalse(expiresAt.isBefore(date));
      Assert.assertTrue(maxAge <= expiresAt.getEpochSecond() - date.getEpochSecond());
    }
  }

  @Test
  public void getErrors() throws Exception {
    // too short to be a request
    Assert.assertEquals(400, get("/MEU=").status);
    // neither Base64 nor URL encoded
    Assert.assertEquals(400, get("/" + "!".repeat(20)).status);
    // longer than the maximal request size (4096)
    Assert.assertEquals(414, get("/" + "A".repeat(5000)).status);
  }

  @Test
  public void invalidPercentEncodingIsBadRequest() throws Exception {
    String b64 = Base64.encodeToString(request());
    // %ZZ is no hex number
    Assert.assertEquals(400, get("/%ZZ" + b64).status);
    Assert.assertEquals(400, get("/" + b64 + "%G1").status);
    // truncated escape at the end, after a valid one
    Assert.assertEquals(400, get("/" + escape(b64.charAt(0)) + b64.substring(1) + "%4").status);
    Assert.assertEquals(400, get("/%2B" + b64 + "%").status);
    // a valid escape is still accepted, also with lower case hex digits
    Assert.assertEquals(200,
        get("/" + escape(b64.charAt(0)).toLowerCase(Locale.ROOT) + b64.substring(1)).status);
  }

  // ---------------------------------------------------------------- POST and others

  @Test
  public void post() throws Exception {
    Resp resp = call("POST", "/", "application/ocsp-request", request());
    assertSuccessful(resp);
    Assert.assertNull("no caching headers for POST", resp.header("ETag"));
  }

  @Test
  public void postErrors() throws Exception {
    Assert.assertEquals(415, call("POST", "/", "application/octet-stream", request()).status);
    Assert.assertEquals(415, call("POST", "/", null, request()).status);
    Assert.assertEquals(413,
        call("POST", "/", "application/ocsp-request", new byte[5000]).status);
    // not an OCSP request: an OCSP error response
    Resp resp = call("POST", "/", "application/ocsp-request", new byte[]{1, 2, 3});
    Assert.assertEquals(200, resp.status);
    Assert.assertEquals(OCSPResponseStatus.MALFORMED_REQUEST,
        OCSPResponse.fromEncoded(resp.body).getResponseStatus());
  }

  @Test
  public void unsupportedMethod() throws Exception {
    Assert.assertEquals(405, call("PUT", "/", "application/ocsp-request", request()).status);
  }

  // ---------------------------------------------------------------- helpers

  /** The percent escape of the char, e.g. %41 for 'A'. */
  private static String escape(char c) {
    return String.format("%%%02X", (int) c);
  }

  private static byte[] request() throws Exception {
    return OcspTestUtil.request(OcspTestUtil.certId(caCert, serial));
  }

  private static void assertSuccessful(Resp resp) throws Exception {
    Assert.assertEquals(200, resp.status);
    Assert.assertEquals("application/ocsp-response", resp.contentType);
    Assert.assertEquals(OCSPResponseStatus.SUCCESSFUL,
        OCSPResponse.fromEncoded(resp.body).getResponseStatus());
  }

  private static Resp get(String path) throws Exception {
    return call("GET", path, null, null);
  }

  private static Resp call(String method, String path, String contentType, byte[] body)
      throws Exception {
    Req req = new Req(method, path, contentType, body);
    Resp resp = new Resp();
    servlet.service(req, resp);
    return resp;
  }

  private static final class Req implements XiHttpRequest {

    private final String method;

    private final String contentType;

    private final byte[] body;

    private final Map<String, Object> attributes = new HashMap<>();

    Req(String method, String path, String contentType, byte[] body) {
      this.method = method;
      this.contentType = contentType;
      this.body = body == null ? new byte[0] : body;
      attributes.put(HttpConstants.ATTR_XIPKI_PATH, path);
    }

    @Override
    public String getHeader(String headerName) {
      return "content-type".equalsIgnoreCase(headerName) ? contentType : null;
    }

    @Override
    public String getParameter(String paramName) {
      return null;
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
      return contentType;
    }

    @Override
    public Object getAttribute(String name) {
      return attributes.get(name);
    }

    @Override
    public String getRequestURI() {
      return (String) attributes.get(HttpConstants.ATTR_XIPKI_PATH);
    }

    @Override
    public InputStream getInputStream() {
      return new ByteArrayInputStream(body);
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
      return null;
    }

  }

  private static final class Resp implements XiHttpResponse {

    private int status = 200;

    private String contentType;

    private final Map<String, String> headers = new HashMap<>();

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    private byte[] body;

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
      this.contentType = type;
    }

    @Override
    public void addHeader(String name, String value) {
      headers.put(name.toLowerCase(Locale.ROOT), value);
    }

    @Override
    public void setHeader(String name, String value) {
      headers.put(name.toLowerCase(Locale.ROOT), value);
    }

    @Override
    public void setContentLength(int len) {
    }

    @Override
    public OutputStream getOutputStream() {
      return new OutputStream() {
        @Override
        public void write(int b) {
          out.write(b);
          body = out.toByteArray();
        }

        @Override
        public void write(byte[] b, int off, int len) {
          out.write(b, off, len);
          body = out.toByteArray();
        }
      };
    }

    String header(String name) {
      return headers.get(name.toLowerCase(Locale.ROOT));
    }

  }

}
