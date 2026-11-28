// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.servlet;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.sdk.ErrorCode;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.NameType;
import org.xipki.ca.sdk.RevokeCertsRequest;
import org.xipki.ca.server.SdkResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.http.HttpConstants;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;
import org.xipki.util.misc.NameId;
import org.xipki.util.misc.PemEncoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The SDK interface of the CA ({@code CaHttpFilter.HttpRaServlet} with {@link SdkResponder}):
 * authentication of the requestor by the TLS client certificate, directly and behind a
 * reverse proxy, permissions, paths and the HTTP status codes of the errors.
 *
 * @author Lijun Liao (xipki)
 */
public class HttpRaServletH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static CaH2TestEnv env;

  /** Requestor with all permissions. */
  private static X509Cert fullCert;

  /** Requestor with only the permission to enroll. */
  private static X509Cert enrollOnlyCert;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    CaManagerImpl caManager = env.caManager();
    fullCert = newCert();
    enrollOnlyCert = newCert();
    addRequestor(caManager, "ra-full", fullCert, PermissionConstants.ALL);
    addRequestor(caManager, "ra-enroll", enrollOnlyCert, PermissionConstants.ENROLL_CERT);
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  // ---------------------------------------------------------------- authentication

  @Test
  public void requestorIsAuthenticatedByTheClientCertificate() throws Exception {
    Resp resp = call("NO", req("GET", "/" + CA + "/cacert").cert(fullCert));
    Assert.assertEquals(200, resp.status);
    Assert.assertEquals("application/cbor", resp.contentType);
  }

  @Test
  public void withoutClientCertificate() throws Exception {
    assertError(401, ErrorCode.UNAUTHORIZED, call("NO", req("GET", "/" + CA + "/cacert")));
  }

  @Test
  public void noCaInformationBeforeAuthentication() throws Exception {
    // unknown CA, malformed body: without client certificate always 401
    assertError(401, ErrorCode.UNAUTHORIZED, call("NO", req("GET", "/unknown-ca/cacert")));
    assertError(401, ErrorCode.UNAUTHORIZED,
        call("NO", req("POST", "/-/revoke_cert").body(new byte[]{1, 2, 3})));
  }

  @Test
  public void unknownClientCertificate() throws Exception {
    assertError(401, ErrorCode.NOT_PERMITTED,
        call("NO", req("GET", "/" + CA + "/cacert").cert(newCert())));
  }

  @Test
  public void proxyHeadersAreIgnoredWithoutReverseProxyMode() throws Exception {
    // a client must not be able to authenticate itself with the headers of a reverse proxy
    Req req = req("GET", "/" + CA + "/cacert")
        .header("SSL_CLIENT_VERIFY", "SUCCESS")
        .header("SSL_CLIENT_CERT", pem(fullCert));
    assertError(401, ErrorCode.UNAUTHORIZED, call("NO", req));
  }

  @Test
  public void behindReverseProxy() throws Exception {
    // PEM as sent by Apache
    Assert.assertEquals(200, call("APACHE", req("GET", "/" + CA + "/cacert")
        .header("SSL_CLIENT_VERIFY", "SUCCESS")
        .header("SSL_CLIENT_CERT", pem(fullCert))).status);

    // URL-encoded PEM as sent by nginx ($ssl_client_escaped_cert)
    Assert.assertEquals(200, call("NGINX", req("GET", "/" + CA + "/cacert")
        .header("SSL_CLIENT_VERIFY", "SUCCESS")
        .header("SSL_CLIENT_CERT", URLEncoder.encode(pem(fullCert), StandardCharsets.UTF_8)))
        .status);

    // verification of the client certificate failed at the proxy
    assertError(401, ErrorCode.UNAUTHORIZED, call("APACHE", req("GET", "/" + CA + "/cacert")
        .header("SSL_CLIENT_VERIFY", "FAILED:certificate expired")
        .header("SSL_CLIENT_CERT", pem(fullCert))));

    // the TLS client certificate of the connection (the proxy's) is not used
    assertError(401, ErrorCode.UNAUTHORIZED,
        call("APACHE", req("GET", "/" + CA + "/cacert").cert(fullCert)));
  }

  // ---------------------------------------------------------------- permissions

  @Test
  public void missingPermission() throws Exception {
    RevokeCertsRequest revoke = new RevokeCertsRequest(null,
        new NameType(env.caCert().subject()), null, new RevokeCertsRequest.Entry[]{
            new RevokeCertsRequest.Entry(BigInteger.ONE, CrlReason.KEY_COMPROMISE, null)});
    byte[] body = revoke.encode();

    assertError(401, ErrorCode.NOT_PERMITTED,
        call("NO", req("POST", "/-/revoke_cert").cert(enrollOnlyCert).body(body)));
    // with the permission: the request is processed, the certificate is unknown
    Resp resp = call("NO", req("POST", "/-/revoke_cert").cert(fullCert).body(body));
    Assert.assertEquals(200, resp.status);
  }

  // ---------------------------------------------------------------- paths and errors

  @Test
  public void pathsAndMethods() throws Exception {
    assertError(404, ErrorCode.PATH_NOT_FOUND,
        call("NO", req("GET", "/unknown-ca/cacert").cert(fullCert)));
    assertError(404, ErrorCode.PATH_NOT_FOUND, call("NO", req("GET", "/" + CA).cert(fullCert)));
    assertError(404, ErrorCode.PATH_NOT_FOUND,
        call("NO", req("GET", "/" + CA + "/").cert(fullCert)));
    Assert.assertEquals(405, call("NO", req("PUT", "/" + CA + "/cacert").cert(fullCert)).status);
  }

  @Test
  public void malformedRequestIsBadRequest() throws Exception {
    assertError(400, ErrorCode.BAD_REQUEST, call("NO",
        req("POST", "/-/revoke_cert").cert(fullCert).body(new byte[]{1, 2, 3})));
  }

  // ---------------------------------------------------------------- helpers

  private static void addRequestor(CaManagerImpl caManager, String name, X509Cert cert,
                                   int permissions) throws Exception {
    NameId ident = new NameId(null, name);
    caManager.addRequestor(new RequestorEntry(ident, RequestorEntry.TYPE_CERT, pem(cert)));
    caManager.addRequestorToCa(new CaHasRequestorEntry(ident, new Permissions(permissions),
        List.of("all")), CA);
  }

  private static String pem(X509Cert cert) {
    return new String(PemEncoder.encode(cert.getEncoded(), PemEncoder.PemLabel.CERTIFICATE),
        StandardCharsets.US_ASCII);
  }

  private static X509Cert newCert() throws Exception {
    char[] password = "CHANGEIT".toCharArray();
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(password)).keystore();
    try (InputStream in = new ByteArrayInputStream(keystore)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, password, null, password,
          (X509Cert) null).certChain()[0];
    }
  }

  private static void assertError(int httpStatus, ErrorCode code, Resp resp) throws Exception {
    Assert.assertEquals("HTTP status", httpStatus, resp.status);
    ErrorResponse error = ErrorResponse.decode(resp.body);
    Assert.assertEquals(error.message(), code, error.code());
  }

  /** Calls the HttpRaServlet with the given reverse proxy mode. */
  private static Resp call(String reverseProxyMode, Req req) throws Exception {
    SdkResponder responder = new SdkResponder(reverseProxyMode, env.caManager());
    Class<?> clazz = Class.forName(CaHttpFilter.class.getName() + "$HttpRaServlet");
    Constructor<?> constructor = clazz.getDeclaredConstructor(boolean.class, SdkResponder.class);
    constructor.setAccessible(true);
    Object servlet = constructor.newInstance(false, responder);
    Method service = clazz.getDeclaredMethod("service", XiHttpRequest.class,
        XiHttpResponse.class);
    service.setAccessible(true);
    Resp resp = new Resp();
    service.invoke(servlet, req, resp);
    return resp;
  }

  private static Req req(String method, String path) {
    return new Req(method, path);
  }

  private static final class Req implements XiHttpRequest {

    private final String method;

    private final Map<String, String> headers = new HashMap<>();

    private final Map<String, Object> attributes = new HashMap<>();

    private X509Certificate[] certs;

    private byte[] body = new byte[0];

    Req(String method, String path) {
      this.method = method;
      attributes.put(HttpConstants.ATTR_XIPKI_PATH, path);
    }

    Req header(String name, String value) {
      headers.put(name.toLowerCase(Locale.ROOT), value);
      return this;
    }

    Req cert(X509Cert cert) throws Exception {
      certs = new X509Certificate[]{(X509Certificate) CertificateFactory.getInstance("X.509")
          .generateCertificate(new ByteArrayInputStream(cert.getEncoded()))};
      return this;
    }

    Req body(byte[] body) {
      this.body = body;
      return this;
    }

    @Override
    public String getHeader(String headerName) {
      return headers.get(headerName.toLowerCase(Locale.ROOT));
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
      return "application/cbor";
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
      return certs;
    }

  }

  private static final class Resp implements XiHttpResponse {

    private int status = 200;

    private String contentType;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    private byte[] body = new byte[0];

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
    }

    @Override
    public void setHeader(String name, String value) {
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

  }

}
