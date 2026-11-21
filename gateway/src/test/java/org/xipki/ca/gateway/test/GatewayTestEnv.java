// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.x500.X500Name;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.gateway.GatewayConf;
import org.xipki.ca.gateway.PopControl;
import org.xipki.ca.gateway.est.EstResponder;
import org.xipki.ca.gateway.rest.RestResponder;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.SdkClient;
import org.xipki.ca.sdk.SdkResponse;
import org.xipki.ca.server.SdkResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.auth.SimpleRequestorAuthenticator;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.misc.NameId;
import org.xipki.util.misc.PemEncoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * The environment of the gateway tests: the CA of {@link CaH2TestEnv}, whose SDK interface
 * ({@link SdkResponder}) is served by the HTTP server of the JDK, and the EST and REST
 * responders, which access the CA via a real {@link SdkClient}.
 * <p>
 * The gateway is registered in the CA as requestor with its certificate, which is passed to
 * the CA as TLS client certificate. The gateway authenticates its clients with
 * {@link SimpleRequestorAuthenticator}: user {@link #USER} may do everything, user
 * {@link #USER_NO_ENROLL} may not enroll certificates.
 *
 * @author Lijun Liao (xipki)
 */
public final class GatewayTestEnv implements AutoCloseable {

  public static final String CA = CaH2TestEnv.CA_NAME;

  public static final String PROFILE = CaH2TestEnv.PROFILE_TLS;

  public static final String USER = "user1";

  public static final String PASSWORD = "password1";

  public static final String USER_NO_ENROLL = "user2";

  public static final String PASSWORD_NO_ENROLL = "password2";

  private final CaH2TestEnv ca;

  private final HttpServer raServer;

  private final RestResponder restResponder;

  private final EstResponder estResponder;

  private final SdkClient sdk;

  private final PopControl popControl;

  public GatewayTestEnv() throws Exception {
    ca = new CaH2TestEnv();
    CaManagerImpl caManager = ca.caManager();

    // the gateway as requestor of the CA
    X509Cert gatewayCert = newCert();
    NameId gatewayIdent = new NameId(null, "gateway");
    String gatewayPem = new String(PemEncoder.encode(gatewayCert.getEncoded(),
        PemEncoder.PemLabel.CERTIFICATE), StandardCharsets.US_ASCII);
    caManager.addRequestor(new RequestorEntry(gatewayIdent, RequestorEntry.TYPE_CERT, gatewayPem));
    caManager.addRequestorToCa(new CaHasRequestorEntry(gatewayIdent,
        new Permissions(PermissionConstants.ALL), List.of("all")), CA);

    X509Certificate jceGatewayCert = (X509Certificate) CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(gatewayCert.getEncoded()));
    SdkResponder sdkResponder = new SdkResponder(null, caManager);
    raServer = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    raServer.createContext("/ra", exchange -> serveRa(exchange, sdkResponder, jceGatewayCert));
    raServer.start();

    sdk = new SdkClient(
        "http://127.0.0.1:" + raServer.getAddress().getPort() + "/ra/", null, null);

    SimpleRequestorAuthenticator authenticator = new SimpleRequestorAuthenticator();
    authenticator.init(writeRequestorsConf().toString(), null);

    popControl = new PopControl(new GatewayConf.PopControlConf(null, null, null), null);
    GatewayConf.CaProfilesControl caProfiles = new GatewayConf.CaProfilesControl(List.of(
        new GatewayConf.CaProfileConf("default", CA, PROFILE),
        new GatewayConf.CaProfileConf("tls", CA, PROFILE)));

    restResponder = new RestResponder(sdk, ca.securities().securityFactory(), authenticator,
        popControl, caProfiles, null);
    estResponder = new EstResponder(sdk, ca.securities().securityFactory(), authenticator,
        popControl, caProfiles, null);
  }

  public CaH2TestEnv ca() {
    return ca;
  }

  public RestResponder restResponder() {
    return restResponder;
  }

  public EstResponder estResponder() {
    return estResponder;
  }

  /** The SDK client of the gateway to the CA. */
  public SdkClient sdk() {
    return sdk;
  }

  public PopControl popControl() {
    return popControl;
  }

  @Override
  public void close() {
    raServer.stop(0);
    ca.close();
  }

  /** Returns the value of the HTTP header Authorization for basic authentication. */
  public static String basicAuth(String user, String password) {
    return "Basic " + Base64.getEncoder().encodeToString(
        (user + ":" + password).getBytes(StandardCharsets.UTF_8));
  }

  /** Returns a DER-encoded PKCS#10 request with a new P-256 key. */
  public static byte[] newCsr(String subject) throws Exception {
    X509KeyPairWithSubjectPublicKeyInfo kp = KeyUtil.generateX509KeyPair2(KeySpec.P256);
    CertificationRequest csr = new CertificationRequest.CsrBuilder(
        new X500Name(subject), kp.subjectPublicKeyInfo())
        .build(KeyUtil.getSigner(kp.keypair().getPrivate(), kp.keypair().getPublic())
            .contentSigner());
    return csr.getEncoded();
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

  private Path writeRequestorsConf() throws IOException {
    String conf = "{\"passwords\": [\n"
        + "  {\"user\": \"" + USER + "\", \"password\": \"" + PASSWORD + "\",\n"
        + "   \"protocols\": [\"ALL\"], \"permissions\": [\"ALL\"],\n"
        + "   \"caProfiles\": [{\"ca\": \"ALL\", \"profiles\": [\"ALL\"]}]},\n"
        + "  {\"user\": \"" + USER_NO_ENROLL + "\", \"password\": \"" + PASSWORD_NO_ENROLL
        + "\",\n"
        + "   \"protocols\": [\"ALL\"], \"permissions\": [\"REVOKE_CERT\", \"UNSUSPEND_CERT\"],\n"
        + "   \"caProfiles\": [{\"ca\": \"ALL\", \"profiles\": [\"ALL\"]}]}\n"
        + "]}\n";
    Path file = Files.createTempFile("gateway-requestors", ".json");
    Files.writeString(file, conf);
    return file;
  }

  /** Serves the SDK interface of the CA, like the RA servlet of the CA. */
  private static void serveRa(HttpExchange exchange, SdkResponder responder,
                              X509Certificate clientCert) throws IOException {
    try {
      byte[] request;
      try (InputStream in = exchange.getRequestBody()) {
        request = in.readAllBytes();
      }
      boolean post = "POST".equalsIgnoreCase(exchange.getRequestMethod());
      String path = exchange.getRequestURI().getPath().substring("/ra".length());

      TestHttpRequest httpRequest = new TestHttpRequest(exchange.getRequestMethod());
      httpRequest.setCertificateChain(clientCert);
      SdkResponse response = responder.service(path, post ? request : null, httpRequest);

      byte[] body = response == null ? new byte[0] : response.encode();
      int status = (response instanceof ErrorResponse) ? 400 : 200;
      exchange.getResponseHeaders().set("Content-Type", "application/cbor");
      exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
      if (body.length > 0) {
        try (OutputStream out = exchange.getResponseBody()) {
          out.write(body);
        }
      }
    } catch (Exception ex) {
      throw new IOException(ex);
    } finally {
      exchange.close();
    }
  }

}
