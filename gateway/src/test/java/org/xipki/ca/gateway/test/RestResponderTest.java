// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.x509.CRLEntry;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.gateway.rest.RestResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.codec.Hex;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.http.HttpResponse;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.xipki.ca.gateway.test.GatewayTestEnv.CA;
import static org.xipki.ca.gateway.test.GatewayTestEnv.PASSWORD;
import static org.xipki.ca.gateway.test.GatewayTestEnv.PASSWORD_NO_ENROLL;
import static org.xipki.ca.gateway.test.GatewayTestEnv.PROFILE;
import static org.xipki.ca.gateway.test.GatewayTestEnv.USER;
import static org.xipki.ca.gateway.test.GatewayTestEnv.USER_NO_ENROLL;
import static org.xipki.ca.gateway.test.GatewayTestEnv.basicAuth;
import static org.xipki.ca.gateway.test.GatewayTestEnv.newCsr;

/**
 * Integration test of the REST API ({@link RestResponder}) against a real CA, see
 * {@link GatewayTestEnv}.
 *
 * @author Lijun Liao (xipki)
 */
public class RestResponderTest {

  private static final String CT_PKCS10 = "application/pkcs10";

  private static GatewayTestEnv env;

  private static RestResponder responder;

  private static CaManagerImpl caManager;

  private static X509Cert caCert;

  @BeforeClass
  public static void init() throws Exception {
    env = new GatewayTestEnv();
    responder = env.restResponder();
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
  public void cacert() throws Exception {
    HttpResponse resp = get("/cacert");
    assertOk(resp, "application/pkix-cert");
    Assert.assertArrayEquals(caCert.getEncoded(), resp.body());
  }

  @Test
  public void cacerts() {
    HttpResponse resp = get("/" + CA + "/cacerts");
    assertOk(resp, "application/x-pem-file");
    Assert.assertTrue(new String(resp.body(), StandardCharsets.US_ASCII)
        .contains("-----BEGIN CERTIFICATE-----"));
  }

  @Test
  public void enrollCert() throws Exception {
    X509Cert cert = enroll("/enroll-cert", "rest-enroll.example.org");
    Assert.assertEquals(caCert.subject(), cert.issuer());
    cert.verify(caCert.publicKey());
    Assert.assertTrue(cert.subjectText().contains("rest-enroll.example.org"));

    CertWithRevocationInfo stored = caManager.getCert(CA, cert.serialNumber());
    Assert.assertNotNull("certificate in the CA", stored);
    Assert.assertEquals(PROFILE, stored.certprofile());
  }

  @Test
  public void enrollCertWithAliasAndCaNamePaths() throws Exception {
    // <alias>/<command>
    enroll("/tls/enroll-cert", "rest-alias.example.org");

    // <CA name>/<command>?profile=<profile>
    TestHttpRequest req = post(CT_PKCS10, USER, PASSWORD).parameter("profile", PROFILE);
    HttpResponse resp = service("/" + CA + "/enroll-cert",
        newCsr("CN=rest-ca.example.org,O=myorg,C=DE"), req);
    assertOk(resp, "application/pkix-cert");
  }

  @Test
  public void enrollServerKeygen() throws Exception {
    byte[] body = "subject=CN=rest-keygen.example.org,O=myorg,C=DE\n"
        .getBytes(StandardCharsets.UTF_8);
    HttpResponse resp = service("/enroll-serverkeygen", body,
        post("text/plain", USER, PASSWORD));
    assertOk(resp, "application/x-pem-file");
    String pem = new String(resp.body(), StandardCharsets.US_ASCII);
    Assert.assertTrue(pem.contains("PRIVATE KEY-----"));
    Assert.assertTrue(pem.contains("-----BEGIN CERTIFICATE-----"));
  }

  @Test
  public void revokeAndUnsuspend() throws Exception {
    X509Cert cert = enroll("/enroll-cert", "rest-revoke.example.org");
    String serial = cert.serialNumber().toString();

    HttpResponse resp = service("/revoke-cert", null, post(null, USER, PASSWORD)
        .parameter("ca-sha1", caSha1()).parameter("serial-number", serial)
        .parameter("reason", "certificateHold"));
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals(CrlReason.CERTIFICATE_HOLD,
        caManager.getCert(CA, cert.serialNumber()).revInfo().reason());

    resp = service("/unsuspend-cert", null, post(null, USER, PASSWORD)
        .parameter("ca-sha1", caSha1()).parameter("serial-number", serial));
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertFalse(caManager.getCert(CA, cert.serialNumber()).isRevoked());
  }

  @Test
  public void crlContainsRevokedCertificate() throws Exception {
    X509Cert cert = enroll("/enroll-cert", "rest-crl.example.org");
    HttpResponse resp = service("/revoke-cert", null, post(null, USER, PASSWORD)
        .parameter("ca-sha1", caSha1())
        .parameter("serial-number", cert.serialNumber().toString())
        .parameter("reason", "keyCompromise"));
    Assert.assertEquals(200, resp.statusCode());
    caManager.generateCrlOnDemand(CA);

    resp = get("/crl");
    assertOk(resp, "application/pkix-crl");
    Set<BigInteger> serials = new HashSet<>();
    List<CRLEntry> entries = CertificateList.fromEncoded(resp.body()).getRevokedCertificates();
    for (CRLEntry entry : entries) {
      serials.add(entry.getUserCertificate().getValue());
    }
    Assert.assertTrue(serials.contains(cert.serialNumber()));
  }

  @Test
  public void revokeUnknownCertificate() throws Exception {
    HttpResponse resp = service("/revoke-cert", null, post(null, USER, PASSWORD)
        .parameter("ca-sha1", caSha1()).parameter("serial-number", "123456789"));
    assertFailure(resp, 400, "badCertId");
  }

  @Test
  public void wrongPasswordIsRejected() throws Exception {
    HttpResponse resp = service("/enroll-cert", newCsr("CN=x.example.org,O=myorg,C=DE"),
        post(CT_PKCS10, USER, "wrong"));
    Assert.assertEquals(401, resp.statusCode());
  }

  @Test
  public void missingCredentialsAreRejected() throws Exception {
    HttpResponse resp = service("/enroll-cert", newCsr("CN=x.example.org,O=myorg,C=DE"),
        new TestHttpRequest("POST").header("Content-Type", CT_PKCS10));
    Assert.assertEquals(401, resp.statusCode());
  }

  @Test
  public void enrollWithoutPermissionIsRejected() throws Exception {
    HttpResponse resp = service("/enroll-cert", newCsr("CN=x.example.org,O=myorg,C=DE"),
        post(CT_PKCS10, USER_NO_ENROLL, PASSWORD_NO_ENROLL));
    assertFailure(resp, 401, "notAuthorized");
  }

  @Test
  public void invalidCsrIsRejected() {
    HttpResponse resp = service("/enroll-cert", new byte[] {0x30, 0x03, 0x02, 0x01, 0x01},
        post(CT_PKCS10, USER, PASSWORD));
    assertFailure(resp, 400, "badRequest");
  }

  @Test
  public void subjectNotAllowedByProfileIsRejected() throws Exception {
    // the profile requires a FQDN as common name
    HttpResponse resp = service("/enroll-cert", newCsr("CN=not a domain,O=myorg,C=DE"),
        post(CT_PKCS10, USER, PASSWORD));
    assertFailure(resp, 400, "badCertTemplate");
  }

  @Test
  public void wrongContentTypeIsRejected() throws Exception {
    HttpResponse resp = service("/enroll-cert", newCsr("CN=x.example.org,O=myorg,C=DE"),
        post("application/octet-stream", USER, PASSWORD));
    Assert.assertEquals(415, resp.statusCode());
  }

  @Test
  public void unknownCommandIsRejected() {
    Assert.assertEquals(404, get("/unknown-command").statusCode());
  }

  // ----- helpers -----

  private static X509Cert enroll(String path, String commonName) throws Exception {
    HttpResponse resp = service(path, newCsr("CN=" + commonName + ",O=myorg,C=DE"),
        post(CT_PKCS10, USER, PASSWORD));
    assertOk(resp, "application/pkix-cert");
    return X509Util.parseCert(resp.body());
  }

  private static String caSha1() throws Exception {
    return Hex.encode(HashAlgo.SHA1.hash(caCert.getEncoded()));
  }

  private static TestHttpRequest post(String contentType, String user, String password) {
    TestHttpRequest req = new TestHttpRequest("POST")
        .header("Authorization", basicAuth(user, password));
    if (contentType != null) {
      req.header("Content-Type", contentType);
    }
    return req;
  }

  private static HttpResponse get(String path) {
    return service(path, null, new TestHttpRequest("GET"));
  }

  private static HttpResponse service(String path, byte[] body, TestHttpRequest req) {
    return responder.service(path, body, req, new AuditEvent("test"));
  }

  private static void assertOk(HttpResponse resp, String contentType) {
    Assert.assertEquals("HTTP status", 200, resp.statusCode());
    Assert.assertEquals(contentType, resp.contentType());
    Assert.assertEquals("accepted", header(resp, "X-xipki-pkistatus"));
  }

  private static void assertFailure(HttpResponse resp, int status, String failInfo) {
    Assert.assertEquals("HTTP status", status, resp.statusCode());
    Assert.assertEquals(failInfo, header(resp, "X-xipki-fail-info"));
  }

  private static String header(HttpResponse resp, String name) {
    List<String> values = resp.headers() == null ? null : resp.headers().get(name);
    return values == null || values.isEmpty() ? null : values.get(0);
  }

}
