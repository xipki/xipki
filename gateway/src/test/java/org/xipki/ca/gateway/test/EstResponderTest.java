// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.ca.gateway.est.EstResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.http.HttpResponse;

import java.nio.charset.StandardCharsets;

import static org.xipki.ca.gateway.test.GatewayTestEnv.CA;
import static org.xipki.ca.gateway.test.GatewayTestEnv.PASSWORD;
import static org.xipki.ca.gateway.test.GatewayTestEnv.PASSWORD_NO_ENROLL;
import static org.xipki.ca.gateway.test.GatewayTestEnv.PROFILE;
import static org.xipki.ca.gateway.test.GatewayTestEnv.USER;
import static org.xipki.ca.gateway.test.GatewayTestEnv.USER_NO_ENROLL;
import static org.xipki.ca.gateway.test.GatewayTestEnv.basicAuth;
import static org.xipki.ca.gateway.test.GatewayTestEnv.newCsr;

/**
 * Integration test of the EST API (RFC 7030 and the xipki extensions with prefix 'u')
 * ({@link EstResponder}) against a real CA, see {@link GatewayTestEnv}.
 *
 * @author Lijun Liao (xipki)
 */
public class EstResponderTest {

  private static final String CT_PKCS10 = "application/pkcs10";

  private static final String CT_PKCS7_CERTS_ONLY = "application/pkcs7-mime; smime-type=certs-only";

  private static GatewayTestEnv env;

  private static EstResponder responder;

  private static CaManagerImpl caManager;

  private static X509Cert caCert;

  @BeforeClass
  public static void init() throws Exception {
    env = new GatewayTestEnv();
    responder = env.estResponder();
    caManager = env.ca().caManager();
    caCert = env.ca().caCert();
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void cacerts() {
    HttpResponse resp = get("/cacerts");
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("application/pkcs7-mime", resp.contentType());
    Assert.assertTrue("base64", resp.isBase64());
    Assert.assertTrue(resp.body().length > caCert.getEncoded().length);
  }

  @Test
  public void ucacert() throws Exception {
    HttpResponse resp = get("/ucacert");
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("application/pkix-cert", resp.contentType());
    Assert.assertArrayEquals(caCert.getEncoded(), resp.body());
  }

  @Test
  public void ucacerts() {
    HttpResponse resp = get("/tls/ucacerts");
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("application/x-pem-file", resp.contentType());
    Assert.assertTrue(new String(resp.body(), StandardCharsets.US_ASCII)
        .contains("-----BEGIN CERTIFICATE-----"));
  }

  @Test
  public void ucaps() {
    HttpResponse resp = get("/ucaps");
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("text/plain", resp.contentType());
  }

  @Test
  public void csrattrs() {
    HttpResponse resp = get("/csrattrs");
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("application/csrattrs", resp.contentType());
  }

  @Test
  public void ucrl() throws Exception {
    caManager.generateCrlOnDemand(CA);
    HttpResponse resp = get("/ucrl");
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("application/pkix-crl", resp.contentType());
    Assert.assertEquals(caCert.subject(), CertificateList.fromEncoded(resp.body()).getIssuer());
  }

  @Test
  public void simpleenroll() throws Exception {
    HttpResponse resp = enroll("/simpleenroll", "est-enroll.example.org", USER, PASSWORD);
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals(CT_PKCS7_CERTS_ONLY, resp.contentType());
    Assert.assertTrue("base64", resp.isBase64());
  }

  @Test
  public void usimpleenroll() throws Exception {
    HttpResponse resp = enroll("/usimpleenroll", "est-uenroll.example.org", USER, PASSWORD);
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("application/pkix-cert", resp.contentType());

    X509Cert cert = X509Util.parseCert(resp.body());
    Assert.assertEquals(caCert.subject(), cert.issuer());
    cert.verify(caCert.publicKey());
    Assert.assertNotNull("certificate in the CA", caManager.getCert(CA, cert.serialNumber()));
  }

  @Test
  public void enrollWithCaAndProfileInPath() throws Exception {
    // <CA name>/<profile>/<command>
    HttpResponse resp = enroll("/" + CA + "/" + PROFILE + "/usimpleenroll",
        "est-path.example.org", USER, PASSWORD);
    Assert.assertEquals(200, resp.statusCode());
  }

  @Test
  public void serverkeygen() throws Exception {
    HttpResponse resp = enroll("/serverkeygen", "est-keygen.example.org", USER, PASSWORD);
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertTrue(resp.contentType(), resp.contentType().startsWith("multipart/mixed"));
    String body = new String(resp.body(), StandardCharsets.US_ASCII);
    Assert.assertTrue(body.contains("application/pkcs8"));
    Assert.assertTrue(body.contains(CT_PKCS7_CERTS_ONLY));
  }

  @Test
  public void userverkeygen() throws Exception {
    HttpResponse resp = enroll("/userverkeygen", "est-ukeygen.example.org", USER, PASSWORD);
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("application/x-pem-file", resp.contentType());
    String pem = new String(resp.body(), StandardCharsets.US_ASCII);
    Assert.assertTrue(pem.contains("PRIVATE KEY-----"));
    Assert.assertTrue(pem.contains("-----BEGIN CERTIFICATE-----"));
  }

  @Test
  public void wrongPasswordIsRejected() throws Exception {
    Assert.assertEquals(401,
        enroll("/simpleenroll", "x.example.org", USER, "wrong").statusCode());
  }

  @Test
  public void missingCredentialsAreRejected() throws Exception {
    HttpResponse resp = service("/simpleenroll", newCsr("CN=x.example.org,O=myorg,C=DE"),
        new TestHttpRequest("POST").header("Content-Type", CT_PKCS10));
    Assert.assertEquals(401, resp.statusCode());
  }

  @Test
  public void enrollWithoutPermissionIsRejected() throws Exception {
    Assert.assertEquals(401, enroll("/simpleenroll", "x.example.org",
        USER_NO_ENROLL, PASSWORD_NO_ENROLL).statusCode());
  }

  @Test
  public void subjectNotAllowedByProfileIsRejected() throws Exception {
    // the profile requires a FQDN as common name: a client error, not a server error
    HttpResponse resp = service("/simpleenroll", newCsr("CN=not a domain,O=myorg,C=DE"),
        post(CT_PKCS10, USER, PASSWORD));
    Assert.assertEquals(400, resp.statusCode());
  }

  @Test
  public void invalidCsrIsRejected() {
    HttpResponse resp = service("/simpleenroll", new byte[] {0x30, 0x03, 0x02, 0x01, 0x01},
        post(CT_PKCS10, USER, PASSWORD));
    Assert.assertEquals(400, resp.statusCode());
  }

  @Test
  public void wrongContentTypeIsRejected() throws Exception {
    HttpResponse resp = service("/simpleenroll", newCsr("CN=x.example.org,O=myorg,C=DE"),
        post("application/octet-stream", USER, PASSWORD));
    Assert.assertEquals(415, resp.statusCode());
  }

  @Test
  public void unknownAliasAndCommandAreRejected() {
    Assert.assertEquals(404, get("/unknown-alias/cacerts").statusCode());
    Assert.assertEquals(404, get("/unknown-command").statusCode());
  }

  // ----- helpers -----

  private static HttpResponse enroll(String path, String commonName, String user,
                                     String password) throws Exception {
    return service(path, newCsr("CN=" + commonName + ",O=myorg,C=DE"),
        post(CT_PKCS10, user, password));
  }

  private static TestHttpRequest post(String contentType, String user, String password) {
    return new TestHttpRequest("POST")
        .header("Authorization", basicAuth(user, password))
        .header("Content-Type", contentType);
  }

  private static HttpResponse get(String path) {
    return service(path, null, new TestHttpRequest("GET"));
  }

  private static HttpResponse service(String path, byte[] body, TestHttpRequest req) {
    return responder.service(path, body, req, new AuditEvent("test"));
  }

}
