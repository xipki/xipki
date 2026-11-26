// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.*;
import javax.net.ssl.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.xipki.mgmt.web.ca.CaDomain.*;

/**
 * @author palos
 */
class ManagementTlsTest {
  @TempDir Path directory;

  @Test
  void authenticatesWithClientCertificateAndKeepsHostnameAndRedirectChecks() throws Exception {
    var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    var rootKey = generator.generateKeyPair();
    var leafKey = generator.generateKeyPair();
    Instant now = Instant.now();
    var root =
        Crypto.issue(
            rootKey.getPublic(),
            rootKey.getPrivate(),
            "CN=Test Root",
            "CN=Test Root",
            BigInteger.ONE,
            now.minusSeconds(60),
            now.plusSeconds(3600),
            List.of(
                extension(
                    "2.5.29.19",
                    Der.sequence(
                        Der.tagged(1, new byte[] {(byte) 255}), Der.integer(BigInteger.ONE))),
                extension("2.5.29.15", Der.tagged(3, new byte[] {1, 6}))));
    var leaf =
        Crypto.issue(
            leafKey.getPublic(),
            rootKey.getPrivate(),
            "CN=Management Endpoint",
            "CN=Test Root",
            BigInteger.TWO,
            now.minusSeconds(60),
            now.plusSeconds(3600),
            List.of(
                extension("2.5.29.19", Der.sequence()),
                extension("2.5.29.15", Der.tagged(3, new byte[] {5, (byte) 160})),
                extension("2.5.29.17", Der.sequence(Der.tagged(135, new byte[] {127, 0, 0, 1})))));
    char[] password = "test-only credential".toCharArray();
    var store = KeyStore.getInstance("PKCS12");
    store.load(null, password);
    store.setKeyEntry(
        "main",
        leafKey.getPrivate(),
        password,
        new Certificate[] {leaf.toJceCert(), root.toJceCert()});
    Path identity = directory.resolve("client.p12");
    try (var out = Files.newOutputStream(identity)) {
      store.store(out, password);
    }
    Path anchors = directory.resolve("roots.pem");
    Files.writeString(
        anchors,
        "-----BEGIN CERTIFICATE-----\n"
            + Base64.getMimeEncoder(64, new byte[] {10}).encodeToString(root.getEncoded())
            + "\n-----END CERTIFICATE-----\n",
        StandardCharsets.US_ASCII);
    var trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    trust.setCertificateEntry("root", root.toJceCert());
    var km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    km.init(store, password);
    var tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tm.init(trust);
    var ssl = SSLContext.getInstance("TLS");
    ssl.init(km.getKeyManagers(), tm.getTrustManagers(), new SecureRandom());
    var server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setHttpsConfigurator(
        new HttpsConfigurator(ssl) {
          @Override
          public void configure(HttpsParameters parameters) {
            var p = ssl.getDefaultSSLParameters();
            p.setNeedClientAuth(true);
            parameters.setSSLParameters(p);
          }
        });
    var requests = new AtomicInteger();
    var authenticated = new AtomicBoolean();
    var method = new AtomicReference<String>();
    server.createContext(
        "/ca/mgmt/",
        exchange -> {
          try {
            authenticated.set(
                ((HttpsExchange) exchange).getSSLSession().getPeerCertificates().length > 0);
            requests.incrementAndGet();
            method.set(exchange.getRequestMethod());
            assertEquals("application/json", exchange.getRequestHeaders().getFirst("Content-Type"));
            exchange.getRequestBody().readAllBytes();
            if (exchange.getRequestURI().getPath().endsWith("restartCaSystem")) {
              exchange.getResponseHeaders().set("Location", "/ca/mgmt/getCaSystemStatus");
              exchange.sendResponseHeaders(302, -1);
            } else {
              String json =
                  exchange.getRequestURI().getPath().endsWith("getCaNames")
                      ? "{\"result\":[\"business-ca\"]}"
                      : "{\"result\":\"STARTED_AS_MASTER\"}";
              byte[] body = json.getBytes(StandardCharsets.UTF_8);
              // The official client deliberately requires the exact management protocol type.
              exchange.getResponseHeaders().set("Content-Type", "application/json");
              exchange.sendResponseHeaders(200, body.length);
              exchange.getResponseBody().write(body);
            }
          } finally {
            exchange.close();
          }
        });
    server.start();
    int port = server.getAddress().getPort();
    try {
      var official =
          OfficialCaMgmtClientFactory.create(
              "https://127.0.0.1:" + port + "/ca/mgmt", identity, password, anchors);
      assertEquals("15000", System.getProperty("sun.net.client.defaultConnectTimeout"));
      assertEquals("60000", System.getProperty("sun.net.client.defaultReadTimeout"));
      assertEquals("false", System.getProperty("sun.net.http.retryPost"));
      assertEquals(
          org.xipki.ca.api.mgmt.CaSystemStatus.STARTED_AS_MASTER,
          official.getCaSystemStatus());
      assertTrue(authenticated.get());
      assertEquals("POST", method.get());
      assertEquals(1, requests.get());
      assertThrows(org.xipki.ca.api.mgmt.CaMgmtException.class, official::restartCaSystem);
      assertEquals(2, requests.get(), "Official client must not follow a mutation redirect");
      var mismatch =
          OfficialCaMgmtClientFactory.create(
              "https://localhost:" + port + "/ca/mgmt", identity, password, anchors);
      assertThrows(org.xipki.ca.api.mgmt.CaMgmtException.class, mismatch::getCaSystemStatus);
      assertEquals(2, requests.get(), "Hostname rejection must happen before request delivery");
      assertThrows(
          IllegalArgumentException.class,
          () ->
              OfficialCaMgmtClientFactory.create(
                  "http://127.0.0.1:" + port + "/ca/mgmt", identity, password, anchors));

      var adapter =
          new OfficialCaMgmtClientAdapter(
              "https://127.0.0.1:" + port + "/ca/mgmt", identity, password, anchors);
      assertEquals(CaSystemStatus.STARTED_AS_MASTER, adapter.getCaSystemStatus());
      assertEquals(Set.of("business-ca"), adapter.getCaNames());
      assertEquals(4, requests.get());
      assertThrows(CaMgmtException.class, adapter::restartCaSystem);
      assertEquals(5, requests.get(), "Adapter mutations must retain hardened transport");
    } finally {
      server.stop(0);
      Arrays.fill(password, '\0');
    }
  }

  private static byte[] extension(String oid, byte[] value) {
    return Der.sequence(Der.oid(oid), Der.tagged(1, new byte[] {(byte) 255}), Der.tagged(4, value));
  }
}
