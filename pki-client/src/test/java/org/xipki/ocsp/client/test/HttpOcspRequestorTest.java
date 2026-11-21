// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.ocsp.OCSPRequest;
import org.xipki.asn1.ocsp.OCSPResponse;
import org.xipki.asn1.ocsp.OCSPResponseStatus;
import org.xipki.asn1.ocsp.OcspCertStatus;
import org.xipki.asn1.ocsp.SingleResponse;
import org.xipki.ocsp.client.HttpOcspRequestor;
import org.xipki.ocsp.client.OcspRequestorException;
import org.xipki.ocsp.client.OcspResponseException;
import org.xipki.ocsp.client.RequestOptions;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.util.http.ReqRespDebug;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Integration test of {@link HttpOcspRequestor} against a real OCSP responder, see
 * {@link OcspTestResponder}. Misbehaving responders are simulated by replaying a response
 * captured for another request.
 *
 * @author Lijun Liao (xipki)
 */
public class HttpOcspRequestorTest {

  private static final BigInteger SN_GOOD = OcspTestResponder.SN_GOOD;

  private static final BigInteger SN_REVOKED = OcspTestResponder.SN_REVOKED;

  private static OcspTestResponder server;

  private static HttpOcspRequestor requestor;

  private static X509Cert caCert;

  @BeforeClass
  public static void init() throws Exception {
    server = new OcspTestResponder();
    caCert = server.caCert();
    requestor = newRequestor(null);
  }

  @AfterClass
  public static void shutdown() {
    if (server != null) {
      server.close();
    }
  }

  @Test
  public void goodAndRevokedViaPost() throws Exception {
    Map<BigInteger, OcspCertStatus> statuses = statuses(requestor.ask(caCert,
        new BigInteger[] {SN_GOOD, SN_REVOKED}, server.url("/ocsp"), options(), null));
    Assert.assertEquals("POST", server.lastMethod());
    Assert.assertEquals(OcspCertStatus.GOOD, statuses.get(SN_GOOD));
    Assert.assertNotNull("revoked", statuses.get(SN_REVOKED).getRevoked());
  }

  @Test
  public void viaGet() throws Exception {
    RequestOptions options = options();
    options.setUseHttpGetForRequest(true);
    // without nonce, so that the request is short enough for GET
    options.setUseNonce(false);
    Map<BigInteger, OcspCertStatus> statuses =
        statuses(requestor.ask(caCert, SN_GOOD, server.url("/ocsp"), options, null));
    Assert.assertEquals("GET", server.lastMethod());
    Assert.assertEquals(OcspCertStatus.GOOD, statuses.get(SN_GOOD));
  }

  @Test
  public void nonceIsSentAndChecked() throws Exception {
    // useNonce is true by default: the responder echoes the nonce, and the client checks it
    ReqRespDebug debug = new ReqRespDebug(true, true);
    requestor.ask(caCert, SN_GOOD, server.url("/ocsp"), options(), debug);
    Assert.assertNotNull("nonce in the request",
        OCSPRequest.fromEncoded(debug.get(0).request()).getTbsRequest().getRequestExtensions());
  }

  @Test
  public void replayedResponseWithOtherNonceIsRejected() throws Exception {
    server.setFixedResponse(capture(SN_GOOD, true));
    Assert.assertThrows(OcspResponseException.OcspNonceUnmatched.class,
        () -> requestor.ask(caCert, SN_GOOD, server.url("/fixed"), options(), null));
  }

  @Test
  public void responseWithoutNonce() throws Exception {
    server.setFixedResponse(capture(SN_GOOD, false));
    Assert.assertThrows(OcspResponseException.OcspNonceUnmatched.class,
        () -> requestor.ask(caCert, SN_GOOD, server.url("/fixed"), options(), null));

    RequestOptions options = options();
    options.setAllowNoNonceInResponse(true);
    Assert.assertEquals(OcspCertStatus.GOOD, statuses(requestor.ask(caCert, SN_GOOD,
        server.url("/fixed"), options, null)).get(SN_GOOD));
  }

  @Test
  public void responseForOtherSerialNumberIsRejected() throws Exception {
    server.setFixedResponse(capture(SN_GOOD, false));
    Assert.assertThrows(OcspResponseException.OcspTargetUnmatched.class,
        () -> requestor.ask(caCert, SN_REVOKED, server.url("/fixed"), noNonce(), null));
  }

  @Test
  public void responseWithTooFewEntriesIsRejected() throws Exception {
    server.setFixedResponse(capture(SN_GOOD, false));
    Assert.assertThrows(OcspResponseException.OcspTargetUnmatched.class,
        () -> requestor.ask(caCert, new BigInteger[] {SN_GOOD, SN_REVOKED},
            server.url("/fixed"), noNonce(), null));
  }

  @Test
  public void unsuccessfulResponseIsReturned() throws Exception {
    // the responder does not know the issuer: malformedRequest
    X509Cert otherIssuer = OcspTestResponder.certOf(OcspTestResponder.newKeystore());
    OCSPResponse resp = requestor.ask(otherIssuer, SN_GOOD, server.url("/ocsp"), options(), null);
    Assert.assertEquals(OCSPResponseStatus.MALFORMED_REQUEST, resp.getResponseStatus());
  }

  @Test
  public void wrongContentTypeIsRejected() {
    Assert.assertThrows(OcspResponseException.ResponderUnreachable.class,
        () -> requestor.ask(caCert, SN_GOOD, server.url("/wrong-type"), options(), null));
  }

  @Test
  public void httpErrorIsRejected() {
    Assert.assertThrows(OcspResponseException.ResponderUnreachable.class,
        () -> requestor.ask(caCert, SN_GOOD, server.url("/error"), options(), null));
  }

  @Test
  public void invalidResponseIsRejected() throws Exception {
    server.setFixedResponse(new byte[] {0x30, 0x03, 0x0a, 0x01});
    Assert.assertThrows(OcspResponseException.InvalidResponse.class,
        () -> requestor.ask(caCert, SN_GOOD, server.url("/fixed"), options(), null));
  }

  @Test
  public void signedRequest() throws Exception {
    HttpOcspRequestor signingRequestor = newRequestor(server.newRequestorConf());
    RequestOptions options = options();
    options.setSignRequest(true);
    Map<BigInteger, OcspCertStatus> statuses = statuses(signingRequestor.ask(caCert,
        new BigInteger[] {SN_GOOD, SN_REVOKED}, server.url("/ocsp"), options, null));
    Assert.assertEquals(2, statuses.size());
    Assert.assertNotNull("signature of the request",
        OCSPRequest.fromEncoded(server.lastRequest()).getOptionalSignature());
  }

  @Test
  public void signedRequestWithoutSignerIsRejected() {
    RequestOptions options = options();
    options.setSignRequest(true);
    Assert.assertThrows(OcspRequestorException.class,
        () -> requestor.ask(caCert, SN_GOOD, server.url("/ocsp"), options, null));
  }

  // ----- helpers -----

  private static HttpOcspRequestor newRequestor(String confFile) {
    HttpOcspRequestor ret = new HttpOcspRequestor();
    ret.setSecurityFactory(server.securities().securityFactory());
    ret.setConfFile(confFile);
    ret.init();
    return ret;
  }

  private static RequestOptions options() {
    return new RequestOptions();
  }

  private static RequestOptions noNonce() {
    RequestOptions options = new RequestOptions();
    options.setUseNonce(false);
    return options;
  }

  /** Returns a real response of the responder to a request for the given serial number. */
  private static byte[] capture(BigInteger serial, boolean useNonce) throws Exception {
    RequestOptions options = options();
    options.setUseNonce(useNonce);
    ReqRespDebug debug = new ReqRespDebug(false, true);
    requestor.ask(caCert, serial, server.url("/ocsp"), options, debug);
    return debug.get(0).response();
  }

  private static Map<BigInteger, OcspCertStatus> statuses(OCSPResponse resp) {
    Assert.assertEquals(OCSPResponseStatus.SUCCESSFUL, resp.getResponseStatus());
    Map<BigInteger, OcspCertStatus> statuses = new LinkedHashMap<>();
    for (Object entry : resp.getBasicOCSPResponse().getResponses()) {
      SingleResponse single = (SingleResponse) entry;
      statuses.put(single.getCertID().serialNumber(), single.getCertStatus());
    }
    return statuses;
  }

}
