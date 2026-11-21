// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.acme.AcmeConf;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Attribute;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.Extensions;
import org.xipki.asn1.x509.GeneralName;
import org.xipki.asn1.x509.GeneralNames;
import org.xipki.ca.gateway.acme.AcmeResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.codec.json.JsonList;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.core.KeySpec;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.ScriptRunner;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.X509KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.http.HttpResponse;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;

import static org.xipki.ca.gateway.test.AcmeTestClient.b64;
import static org.xipki.ca.gateway.test.AcmeTestClient.header;
import static org.xipki.ca.gateway.test.AcmeTestClient.json;

/**
 * Integration test of the ACME server ({@link AcmeResponder}, RFC 8555) against a real CA, see
 * {@link GatewayTestEnv}. The ACME data is stored in an in-memory H2 database, and the dns-01
 * challenges are answered by {@link FakeDnsServer}.
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeResponderTest {

  private static final String HOST = "acme.example.org";

  private static final String BASE_URL = "https://" + HOST + "/acme/";

  private static final String SQL_SCRIPT =
      "../assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/sql/h2/acme-init.h2.sql";

  private static final String ERR_PREFIX = "urn:ietf:params:acme:error:";

  private static final long WAIT_MS = 20_000;

  private static GatewayTestEnv env;

  private static FakeDnsServer dns;

  private static DataSourceWrapper acmeDatasource;

  private static AcmeResponder responder;

  private static CaManagerImpl caManager;

  private static X509Cert caCert;

  @BeforeClass
  public static void init() throws Exception {
    env = new GatewayTestEnv();
    caManager = env.ca().caManager();
    caCert = env.ca().caCert();
    dns = new FakeDnsServer();

    Path workDir = Files.createTempDirectory("xipki-acme-test");
    Path dbConf = workDir.resolve("acme-db.properties");
    Files.writeString(dbConf, "dataSourceClassName = org.h2.jdbcx.JdbcDataSource\n"
        + "dataSource.url = jdbc:h2:mem:acme_" + UUID.randomUUID().toString().replace("-", "")
        + ";DB_CLOSE_DELAY=-1\n"
        + "dataSource.user = sa\n"
        + "dataSource.password = \n"
        + "autoCommit = true\n"
        + "maximumPoolSize = 5\n"
        + "minimumIdle = 1\n");
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(dbConf)) {
      props.load(in);
    }
    acmeDatasource = new DataSourceFactory().createDataSource("acme-test", props);
    ScriptRunner.runScript(acmeDatasource, Paths.get(SQL_SCRIPT).toString(),
        workDir.resolve("acme-init.log"), workDir.resolve("acme-init.error.log"));

    String conf = "{\n"
        + "  \"baseUrl\": \"" + BASE_URL + "\",\n"
        + "  \"dbConf\": \"" + dbConf.toAbsolutePath().toString().replace("\\", "/") + "\",\n"
        + "  \"syncDbSeconds\": 1,\n"
        + "  \"challengeTypes\": [\"dns-01\"],\n"
        + "  \"dnsResolvers\": [\"" + dns.address() + "\"],\n"
        + "  \"caProfiles\": [{\"keyTypes\": [\"1.2.840.10045.2.1\"],"
        + " \"ca\": \"" + GatewayTestEnv.CA + "\", \"tlsProfile\": \"" + GatewayTestEnv.PROFILE
        + "\"}]\n"
        + "}\n";
    AcmeConf.Acme acmeConf = AcmeConf.Acme.parse(JsonParser.parseMap(conf, false));
    responder = new AcmeResponder(env.sdk(), env.ca().securities().securityFactory(),
        env.popControl(), acmeConf, workDir.toString());
    responder.start();
  }

  @AfterClass
  public static void shutdown() {
    if (responder != null) {
      responder.close();
    }
    if (acmeDatasource != null) {
      acmeDatasource.close();
    }
    if (dns != null) {
      dns.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void directory() throws Exception {
    HttpResponse resp = newClient().get(BASE_URL + "directory");
    Assert.assertEquals(200, resp.statusCode());
    JsonMap dir = json(resp);
    Assert.assertEquals(BASE_URL + "new-nonce", dir.getString("newNonce"));
    Assert.assertEquals(BASE_URL + "new-account", dir.getString("newAccount"));
    Assert.assertEquals(BASE_URL + "new-order", dir.getString("newOrder"));
    Assert.assertEquals(BASE_URL + "revoke-cert", dir.getString("revokeCert"));
  }

  @Test
  public void newNonce() {
    AcmeTestClient client = newClient();
    Assert.assertNotEquals(client.newNonce(), client.newNonce());
  }

  @Test
  public void issueAndRevokeCertificate() throws Exception {
    AcmeTestClient client = newAccount();
    String domain = "acme-issue.example.org";

    // order and authorization
    HttpResponse resp = newOrder(client, domain);
    Assert.assertEquals(201, resp.statusCode());
    String orderUrl = header(resp, "Location");
    JsonMap order = json(resp);
    Assert.assertEquals("pending", order.getString("status"));
    String finalizeUrl = order.getString("finalize");
    String authzUrl = order.getStringList("authorizations").get(0);

    // dns-01 challenge
    JsonMap challenge = dns01Challenge(client, authzUrl);
    dns.setTxt("_acme-challenge." + domain, client.dns01Value(challenge.getString("token")));
    resp = client.post(challenge.getString("url"), new JsonMap());
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("valid", waitForStatus(client, authzUrl, "valid"));

    // finalize and download the certificate
    resp = client.post(finalizeUrl, new JsonMap().put("csr", b64(csr(domain))));
    Assert.assertEquals(new String(resp.body(), StandardCharsets.UTF_8), 200, resp.statusCode());
    Assert.assertEquals("valid", waitForStatus(client, orderUrl, "valid"));

    String certUrl = json(client.postAsGet(orderUrl)).getString("certificate");
    resp = client.postAsGet(certUrl);
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals("application/pem-certificate-chain", resp.contentType());
    X509Cert cert = X509Util.parseCert(resp.body());
    Assert.assertEquals(caCert.subject(), cert.issuer());
    cert.verify(caCert.publicKey());
    Assert.assertNotNull("certificate in the CA",
        caManager.getCert(GatewayTestEnv.CA, cert.serialNumber()));

    // revoke
    resp = client.post(BASE_URL + "revoke-cert", new JsonMap()
        .put("certificate", b64(cert.getEncoded())).put("reason", 1));
    Assert.assertEquals(200, resp.statusCode());
    Assert.assertEquals(CrlReason.KEY_COMPROMISE,
        caManager.getCert(GatewayTestEnv.CA, cert.serialNumber()).revInfo().reason());
  }

  @Test
  public void finalizeBeforeAuthorizationIsRejected() throws Exception {
    AcmeTestClient client = newAccount();
    String domain = "acme-notready.example.org";
    JsonMap order = json(newOrder(client, domain));
    HttpResponse resp = client.post(order.getString("finalize"),
        new JsonMap().put("csr", b64(csr(domain))));
    assertProblem(resp, 403, "orderNotReady");
  }

  @Test
  public void reusedNonceIsRejected() throws Exception {
    AcmeTestClient client = newClient();
    String nonce = client.newNonce();
    JsonMap payload = newAccountPayload();
    Assert.assertEquals(201,
        client.postWithNonce(BASE_URL + "new-account", payload, nonce).statusCode());
    assertProblem(client.postWithNonce(BASE_URL + "new-account", payload, nonce),
        400, "badNonce");
  }

  @Test
  public void wrongUrlInProtectedHeaderIsRejected() throws Exception {
    AcmeTestClient client = newAccount();
    // the signed URL does not match the URL of the request
    HttpResponse resp = client.postRawSigned(BASE_URL + "new-order",
        BASE_URL + "revoke-cert", new JsonMap());
    assertProblem(resp, 400, "malformed");
  }

  @Test
  public void wrongContentTypeIsRejected() throws Exception {
    HttpResponse resp = newClient().postRaw(BASE_URL + "new-account", "application/json",
        "{}".getBytes(StandardCharsets.UTF_8));
    assertProblem(resp, 400, "malformed");
  }

  @Test
  public void unknownAccountIsRejected() throws Exception {
    AcmeTestClient client = newClient();
    client.setKid(BASE_URL + "acct/AAAAAAAAAAA");
    HttpResponse resp = newOrder(client, "acme-unknown.example.org");
    Assert.assertTrue("status " + resp.statusCode(),
        resp.statusCode() == 400 || resp.statusCode() == 401 || resp.statusCode() == 403);
  }

  @Test
  public void invalidContactIsRejected() throws Exception {
    AcmeTestClient client = newClient();
    HttpResponse resp = client.post(BASE_URL + "new-account", new JsonMap()
        .put("termsOfServiceAgreed", true)
        .put("contact", new String[] {"tel:+49123456"}));
    assertProblem(resp, 400, "unsupportedContact");
  }

  @Test
  public void unsupportedIdentifierTypeIsRejected() throws Exception {
    AcmeTestClient client = newAccount();
    JsonList identifiers = new JsonList();
    identifiers.add(new JsonMap().put("type", "email").put("value", "a@example.org"));
    HttpResponse resp = client.post(BASE_URL + "new-order",
        new JsonMap().put("identifiers", identifiers));
    assertProblem(resp, 400, "unsupportedIdentifier");
  }

  @Test
  public void csrWithoutTheIdentifierIsRejected() throws Exception {
    AcmeTestClient client = newAccount();
    String domain = "acme-badcsr.example.org";
    HttpResponse resp = newOrder(client, domain);
    String orderUrl = header(resp, "Location");
    JsonMap order = json(resp);

    JsonMap challenge = dns01Challenge(client, order.getStringList("authorizations").get(0));
    dns.setTxt("_acme-challenge." + domain, client.dns01Value(challenge.getString("token")));
    client.post(challenge.getString("url"), new JsonMap());
    waitForStatus(client, order.getStringList("authorizations").get(0), "valid");
    Assert.assertEquals("ready", waitForStatus(client, orderUrl, "ready"));

    resp = client.post(order.getString("finalize"),
        new JsonMap().put("csr", b64(csr("other.example.org"))));
    assertProblem(resp, 400, "badCSR");
  }

  // ----- helpers -----

  private static AcmeTestClient newClient() {
    try {
      return new AcmeTestClient(responder, BASE_URL, HOST);
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
  }

  private static JsonMap newAccountPayload() {
    return new JsonMap().put("termsOfServiceAgreed", true)
        .put("contact", new String[] {"mailto:admin@example.org"});
  }

  /** Returns a client with a new account. */
  private static AcmeTestClient newAccount() throws Exception {
    AcmeTestClient client = newClient();
    HttpResponse resp = client.post(BASE_URL + "new-account", newAccountPayload());
    Assert.assertEquals("new-account", 201, resp.statusCode());
    Assert.assertEquals("valid", json(resp).getString("status"));
    String kid = header(resp, "Location");
    Assert.assertNotNull("account URL", kid);
    client.setKid(kid);
    return client;
  }

  private static HttpResponse newOrder(AcmeTestClient client, String domain) throws Exception {
    JsonList identifiers = new JsonList();
    identifiers.add(new JsonMap().put("type", "dns").put("value", domain));
    return client.post(BASE_URL + "new-order", new JsonMap().put("identifiers", identifiers));
  }

  private static JsonMap dns01Challenge(AcmeTestClient client, String authzUrl)
      throws Exception {
    HttpResponse resp = client.postAsGet(authzUrl);
    Assert.assertEquals(200, resp.statusCode());
    List<JsonMap> challenges = json(resp).getList("challenges").toMapList();
    for (JsonMap m : challenges) {
      if ("dns-01".equals(m.getString("type"))) {
        return m;
      }
    }
    throw new AssertionError("no dns-01 challenge");
  }

  /** Polls the resource (authorization or order) until it has the status, or the timeout. */
  private static String waitForStatus(AcmeTestClient client, String url, String expected)
      throws Exception {
    long deadline = System.currentTimeMillis() + WAIT_MS;
    String status = null;
    while (System.currentTimeMillis() < deadline) {
      status = json(client.postAsGet(url)).getString("status");
      if (expected.equals(status) || "invalid".equals(status)) {
        return status;
      }
      Thread.sleep(200);
    }
    return status;
  }

  /** Returns a DER-encoded CSR whose subjectAltName contains the domain. */
  private static byte[] csr(String domain) throws Exception {
    X509KeyPairWithSubjectPublicKeyInfo kp = KeyUtil.generateX509KeyPair2(KeySpec.P256);
    Extension san = Extension.ofSubjectAlternativeName(false,
        new GeneralNames(GeneralName.ofDnsName(domain)));
    return new CertificationRequest.CsrBuilder(
        new X500Name("CN=" + domain + ",O=myorg,C=DE"), kp.subjectPublicKeyInfo())
        .setAttribute(Attribute.ofExtensionRequest(new Extensions(san)))
        .build(KeyUtil.getSigner(kp.keypair().getPrivate(), kp.keypair().getPublic())
            .contentSigner())
        .getEncoded();
  }

  private static void assertProblem(HttpResponse resp, int status, String type)
      throws Exception {
    Assert.assertEquals("HTTP status", status, resp.statusCode());
    Assert.assertEquals(ERR_PREFIX + type, json(resp).getString("type"));
  }

}
