// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client.test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.xipki.codec.Base64;
import org.xipki.codec.util.ConfPairs;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.ScriptRunner;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.pkix.Securities;
import org.xipki.pkix.cert.CertRevocationInfo;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.audit.Audits;
import org.xipki.util.password.Passwords;
import org.xipki.util.conf.ConfigurableProperties;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Types;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * An OCSP responder for the tests of the OCSP client: the real {@link OcspServer} with the store
 * type {@code xipki-ca-db} on an in-memory H2 CA database, served by the HTTP server of the JDK.
 * <ul>
 *   <li>{@code /ocsp}: answers POST and GET requests.</li>
 *   <li>{@code /fixed}: returns {@link #setFixedResponse(byte[])}, e.g. a replayed response.</li>
 *   <li>{@code /wrong-type}: answers with a wrong content type.</li>
 *   <li>{@code /error}: returns the HTTP status 500.</li>
 * </ul>
 *
 * @author Lijun Liao (xipki)
 */
final class OcspTestResponder implements AutoCloseable {

  static final String CT_RESPONSE = "application/ocsp-response";

  static final String PASSWORD = "CHANGEIT";

  static final BigInteger SN_GOOD = BigInteger.valueOf(0x1001);

  static final BigInteger SN_REVOKED = BigInteger.valueOf(0x1002);

  private static final String SQL_SCRIPT =
      "../assemblies/xipki-setup/src/assembly/unfiltered/" +
      "xipki-mgmt-cli/xipki/sql/h2/ca-init.h2.sql";

  private final Path workDir;

  private final DataSourceWrapper datasource;

  private final Securities securities;

  private final OcspServer ocspServer;

  private final Responder responder;

  private final HttpServer httpServer;

  private final X509Cert caCert;

  private volatile byte[] fixedResponse;

  private volatile byte[] lastRequest;

  private volatile String lastMethod;

  OcspTestResponder() throws Exception {
    workDir = Files.createTempDirectory("xipki-ocsp-client-test");
    Passwords.init(workDir.toString());
    Audits.init("noop", new ConfPairs(), workDir.toString());

    Path dbConf = writeDbConf("ca_" + UUID.randomUUID().toString().replace("-", ""));
    datasource = createDatasource(dbConf);
    ScriptRunner.runScript(datasource, Paths.get(SQL_SCRIPT).toString(),
        workDir.resolve("ca-init.log"), workDir.resolve("ca-init.error.log"));

    byte[] caKeystore = newKeystore();
    caCert = certOf(caKeystore);

    Instant now = Instant.now();
    Instant notBefore = now.minus(30, ChronoUnit.DAYS);
    Instant notAfter = now.plus(30, ChronoUnit.DAYS);
    try (Connection conn = datasource.getConnection()) {
      exec(conn, "INSERT INTO PROFILE (ID,NAME) VALUES (1,'profile1')");
      exec(conn, "INSERT INTO REQUESTOR (ID,NAME) VALUES (1,'requestor1')");
      try (PreparedStatement ps = conn.prepareStatement(
          "INSERT INTO CA (ID,NAME,SUBJECT,CERT) VALUES (1,'ca1',?,?)")) {
        ps.setString(1, caCert.subjectText());
        ps.setString(2, Base64.encodeToString(caCert.getEncoded()));
        ps.executeUpdate();
      }
      addCert(conn, 1, SN_GOOD, notBefore, notAfter, null);
      addCert(conn, 2, SN_REVOKED, notBefore, notAfter, new CertRevocationInfo(
          CrlReason.KEY_COMPROMISE, now.minus(1, ChronoUnit.DAYS), null));
    }

    securities = new Securities();
    securities.init(null, workDir.toString());

    ocspServer = new OcspServer(workDir.toString());
    ocspServer.setSecurityFactory(securities.securityFactory());
    ocspServer.setConfFile(writeResponderConf(dbConf, caKeystore).toString());
    ocspServer.init(true);
    responder = ocspServer.getResponder("responder1");

    httpServer = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    httpServer.createContext("/ocsp", this::handleOcsp);
    httpServer.createContext("/fixed", this::handleFixed);
    httpServer.createContext("/wrong-type", this::handleWrongType);
    httpServer.createContext("/error", this::handleError);
    httpServer.start();
  }

  X509Cert caCert() {
    return caCert;
  }

  Securities securities() {
    return securities;
  }

  URL url(String path) throws IOException {
    return new URL("http://127.0.0.1:" + httpServer.getAddress().getPort() + path);
  }

  void setFixedResponse(byte[] fixedResponse) {
    this.fixedResponse = fixedResponse;
  }

  /** The last request received by {@code /ocsp}. */
  byte[] lastRequest() {
    return lastRequest;
  }

  /** The HTTP method of the last request received by {@code /ocsp}. */
  String lastMethod() {
    return lastMethod;
  }

  /** Writes a new keystore, and returns the signer configuration of the requestor. */
  String newRequestorConf() throws Exception {
    String conf = "{\"signerType\": \"pkcs12\", \"signerConf\": \"password=" + PASSWORD
        + ",keystore=base64:" + Base64.encodeToString(newKeystore()) + "\"}";
    Path file = workDir.resolve("ocsp-requestor-" + UUID.randomUUID() + ".json");
    Files.writeString(file, conf);
    return file.toString();
  }

  @Override
  public void close() {
    httpServer.stop(0);
    ocspServer.close();
    datasource.close();
    securities.close();
  }

  private void handleOcsp(HttpExchange exchange) throws IOException {
    try {
      String method = exchange.getRequestMethod();
      boolean viaGet = "GET".equalsIgnoreCase(method);
      byte[] request;
      if (viaGet) {
        // /ocsp/<URL-encoded base64 of the request>
        String path = exchange.getRequestURI().getRawPath();
        String b64 = URLDecoder.decode(path.substring("/ocsp/".length()), StandardCharsets.UTF_8);
        request = Base64.decode(b64);
      } else {
        try (InputStream in = exchange.getRequestBody()) {
          request = in.readAllBytes();
        }
      }
      lastMethod = method;
      lastRequest = request;
      respond(exchange, 200, CT_RESPONSE, answer(request, viaGet));
    } finally {
      exchange.close();
    }
  }

  private void handleFixed(HttpExchange exchange) throws IOException {
    try {
      try (InputStream in = exchange.getRequestBody()) {
        in.readAllBytes();
      }
      respond(exchange, 200, CT_RESPONSE, fixedResponse);
    } finally {
      exchange.close();
    }
  }

  private void handleWrongType(HttpExchange exchange) throws IOException {
    try {
      byte[] request;
      try (InputStream in = exchange.getRequestBody()) {
        request = in.readAllBytes();
      }
      respond(exchange, 200, "text/plain", answer(request, false));
    } finally {
      exchange.close();
    }
  }

  private void handleError(HttpExchange exchange) throws IOException {
    try {
      try (InputStream in = exchange.getRequestBody()) {
        in.readAllBytes();
      }
      respond(exchange, 500, "text/plain", "error".getBytes(StandardCharsets.UTF_8));
    } finally {
      exchange.close();
    }
  }

  private byte[] answer(byte[] request, boolean viaGet) {
    return ocspServer.answer(responder, request, viaGet).response();
  }

  private static void respond(HttpExchange exchange, int status, String contentType,
                              byte[] body) throws IOException {
    exchange.getResponseHeaders().set("Content-Type", contentType);
    exchange.sendResponseHeaders(status, body.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(body);
    }
  }

  static byte[] newKeystore() throws Exception {
    KeystoreGenerationParameters params =
        new KeystoreGenerationParameters(PASSWORD.toCharArray());
    return KeyUtil.generateX509KeyPair3(KeySpec.P256, params).keystore();
  }

  static X509Cert certOf(byte[] keystore) throws Exception {
    try (InputStream in = new ByteArrayInputStream(keystore)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, PASSWORD.toCharArray(), null,
          PASSWORD.toCharArray(), (X509Cert) null).certChain()[0];
    }
  }

  private static void addCert(Connection conn, long id, BigInteger serial, Instant notBefore,
                              Instant notAfter, CertRevocationInfo revInfo) throws Exception {
    // the certificate itself is not evaluated by the store: use a placeholder
    byte[] placeholder = serial.toByteArray();
    try (PreparedStatement ps = conn.prepareStatement("INSERT INTO CERT "
        + "(ID,CA_ID,SN,PID,RID,FP_S,LUPDATE,NBEFORE,NAFTER,REV,RR,RT,EE,SUBJECT,CRL_SCOPE,"
        + "SHA1,CERT) VALUES (?,1,?,1,1,?,?,?,?,?,?,?,1,?,0,?,?)")) {
      int idx = 1;
      ps.setLong(idx++, id);
      ps.setString(idx++, serial.toString(16));
      ps.setLong(idx++, id); // FP_S
      ps.setLong(idx++, Instant.now().getEpochSecond());
      ps.setLong(idx++, notBefore.getEpochSecond());
      ps.setLong(idx++, notAfter.getEpochSecond());
      ps.setInt(idx++, revInfo == null ? 0 : 1);
      if (revInfo == null) {
        ps.setNull(idx++, Types.SMALLINT);
        ps.setNull(idx++, Types.BIGINT);
      } else {
        ps.setInt(idx++, revInfo.reason().code());
        ps.setLong(idx++, revInfo.revocationTime().getEpochSecond());
      }
      ps.setString(idx++, "CN=ee-" + serial.toString(16));
      ps.setString(idx++, Base64.encodeToString(HashAlgo.SHA1.hash(placeholder)));
      ps.setString(idx, Base64.encodeToString(placeholder));
      ps.executeUpdate();
    }
  }

  private static void exec(Connection conn, String sql) throws Exception {
    try (PreparedStatement ps = conn.prepareStatement(sql)) {
      ps.executeUpdate();
    }
  }

  private Path writeDbConf(String dbName) throws IOException {
    String conf = "dataSourceClassName = org.h2.jdbcx.JdbcDataSource\n"
        + "dataSource.url = jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1\n"
        + "dataSource.user = sa\n"
        + "dataSource.password = \n"
        + "autoCommit = true\n"
        + "maximumPoolSize = 5\n"
        + "minimumIdle = 1\n";
    Path file = workDir.resolve("ca-db.properties");
    Files.writeString(file, conf);
    return file;
  }

  private static DataSourceWrapper createDatasource(Path conf) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(conf)) {
      props.load(in);
    }
    return new DataSourceFactory().createDataSource("ocsp-client-test", props);
  }

  private Path writeResponderConf(Path dbConf, byte[] signerKeystore) throws IOException {
    String dbConfPath = dbConf.toAbsolutePath().toString().replace("\\", "/");
    String conf = "{\n"
        + "  \"master\": true,\n"
        + "  \"unknownIssuerBehaviour\": \"malformedRequest\",\n"
        + "  \"datasources\": [{\"name\": \"datasource1\","
        + " \"conf\": {\"file\": \"" + dbConfPath + "\"}}],\n"
        + "  \"requestOptions\": [{\n"
        + "    \"name\": \"request1\",\n"
        + "    \"hashAlgorithms\": [\"SHA1\", \"SHA256\"],\n"
        + "    \"maxRequestListCount\": 10,\n"
        + "    \"maxRequestSize\": 4096,\n"
        + "    \"nonce\": {\"maxLen\": 32, \"minLen\": 4, \"occurrence\": \"optional\"},\n"
        + "    \"signatureRequired\": false,\n"
        + "    \"supportsHttpGet\": true,\n"
        + "    \"validateSignature\": false,\n"
        + "    \"versions\": [\"v1\"]\n"
        + "  }],\n"
        + "  \"responders\": [{\n"
        + "    \"name\": \"responder1\",\n"
        + "    \"inheritCaRevocation\": true,\n"
        + "    \"mode\": \"RFC6960\",\n"
        + "    \"request\": \"request1\",\n"
        + "    \"response\": \"response1\",\n"
        + "    \"servletPaths\": [\"/\"],\n"
        + "    \"signer\": \"signer1\",\n"
        + "    \"stores\": [\"store1\"]\n"
        + "  }],\n"
        + "  \"responseOptions\": [{\n"
        + "    \"name\": \"response1\",\n"
        + "    \"embedCertsMode\": \"CERT\",\n"
        + "    \"includeCerthash\": false,\n"
        + "    \"includeInvalidityDate\": false,\n"
        + "    \"includeRevReason\": true,\n"
        + "    \"responderIdByName\": true\n"
        + "  }],\n"
        + "  \"signers\": [{\n"
        + "    \"name\": \"signer1\",\n"
        + "    \"type\": \"pkcs12\",\n"
        + "    \"key\": \"password=" + PASSWORD + ",keystore=base64:"
        + Base64.encodeToString(signerKeystore) + "\"\n"
        + "  }],\n"
        + "  \"stores\": [{\n"
        + "    \"name\": \"store1\",\n"
        + "    \"ignoreExpiredCert\": true,\n"
        + "    \"ignoreNotYetValidCert\": true,\n"
        + "    \"includeArchiveCutoff\": false,\n"
        + "    \"includeCrlId\": false,\n"
        + "    \"retentionInterval\": -1,\n"
        + "    \"minNextUpdatePeriod\": \"1d\",\n"
        + "    \"unknownCertBehaviour\": \"unknown\",\n"
        + "    \"updateInterval\": \"10m\",\n"
        + "    \"source\": {\"datasource\": \"datasource1\", \"type\": \"xipki-ca-db\","
        + " \"conf\": {}}\n"
        + "  }]\n"
        + "}\n";
    Path file = workDir.resolve("ocsp-responder.json");
    Files.writeString(file, conf);
    return file;
  }

}
