// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.xipki.ca.gateway.acme.AcmeResponder;
import org.xipki.codec.json.JsonBuilder;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.http.HttpConstants;
import org.xipki.util.http.HttpResponse;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * A minimal ACME client (RFC 8555) which calls the {@link AcmeResponder} directly. Requests are
 * signed with ES256: with the JWK for newAccount, otherwise with the account URL (kid).
 *
 * @author Lijun Liao (xipki)
 */
final class AcmeTestClient {

  static final String CT_JOSE_JSON = "application/jose+json";

  private final AcmeResponder responder;

  private final String baseUrl;

  private final String host;

  private final KeyPair keyPair;

  private final JsonMap jwk;

  private String kid;

  private String nonce;

  AcmeTestClient(AcmeResponder responder, String baseUrl, String host) throws Exception {
    this.responder = responder;
    this.baseUrl = baseUrl;
    this.host = host;

    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
    kpGen.initialize(new ECGenParameterSpec("secp256r1"));
    keyPair = kpGen.generateKeyPair();

    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    jwk = new JsonMap()
        .put("crv", "P-256")
        .put("kty", "EC")
        .put("x", b64(unsigned32(pub.getW().getAffineX())))
        .put("y", b64(unsigned32(pub.getW().getAffineY())));
  }

  String kid() {
    return kid;
  }

  void setKid(String kid) {
    this.kid = kid;
  }

  /** The key authorization of the token (RFC 8555, Section 8.1). */
  String keyAuthorization(String token) {
    String canonJwk = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + jwkValue("x")
        + "\",\"y\":\"" + jwkValue("y") + "\"}";
    return token + "." + b64(HashAlgo.SHA256.hash(canonJwk.getBytes(StandardCharsets.UTF_8)));
  }

  /** The TXT value of the dns-01 challenge for the token (RFC 8555, Section 8.4). */
  String dns01Value(String token) {
    return b64(HashAlgo.SHA256.hash(keyAuthorization(token).getBytes(StandardCharsets.UTF_8)));
  }

  HttpResponse get(String url) {
    return call("GET", url, null, null);
  }

  /** Fetches a fresh nonce from newNonce. */
  String newNonce() {
    HttpResponse resp = call("HEAD", baseUrl + "new-nonce", null, null);
    String ret = header(resp, "Replay-Nonce");
    if (ret == null) {
      throw new IllegalStateException("no Replay-Nonce from new-nonce");
    }
    return ret;
  }

  /** POST with the payload, signed with the JWK if no account (kid) is set. */
  HttpResponse post(String url, JsonMap payload) throws Exception {
    return postWithNonce(url, payload, null);
  }

  /** POST-as-GET (RFC 8555, Section 6.3). */
  HttpResponse postAsGet(String url) throws Exception {
    return post(url, null);
  }

  /** POST with the given nonce, or the last received nonce if {@code null}. */
  HttpResponse postWithNonce(String url, JsonMap payload, String explicitNonce) throws Exception {
    return call("POST", url, CT_JOSE_JSON, jws(url, payload, explicitNonce));
  }

  /** POST to {@code requestUrl} with a JWS signed for {@code signedUrl}. */
  HttpResponse postRawSigned(String requestUrl, String signedUrl, JsonMap payload)
      throws Exception {
    return call("POST", requestUrl, CT_JOSE_JSON, jws(signedUrl, payload, null));
  }

  private byte[] jws(String url, JsonMap payload, String explicitNonce) throws Exception {
    String nonceToUse = explicitNonce;
    if (nonceToUse == null) {
      nonceToUse = (nonce != null) ? nonce : newNonce();
      nonce = null;
    }

    JsonMap protected_ = new JsonMap().put("alg", "ES256").put("nonce", nonceToUse)
        .put("url", url);
    if (kid == null) {
      protected_.put("jwk", jwk);
    } else {
      protected_.put("kid", kid);
    }

    String protectedB64 = b64(JsonBuilder.toJson(protected_).getBytes(StandardCharsets.UTF_8));
    String payloadB64 = payload == null ? ""
        : b64(JsonBuilder.toJson(payload).getBytes(StandardCharsets.UTF_8));
    String signature = b64(sign((protectedB64 + "." + payloadB64)
        .getBytes(StandardCharsets.US_ASCII)));

    JsonMap body = new JsonMap().put("protected", protectedB64).put("payload", payloadB64)
        .put("signature", signature);
    return JsonBuilder.toJson(body).getBytes(StandardCharsets.UTF_8);
  }

  /** Sends the raw body, e.g. a tampered JWS. */
  HttpResponse postRaw(String url, String contentType, byte[] body) {
    return call("POST", url, contentType, body);
  }

  static JsonMap json(HttpResponse resp) throws Exception {
    return JsonParser.parseMap(resp.body(), false);
  }

  static String header(HttpResponse resp, String name) {
    if (resp.headers() == null) {
      return null;
    }
    for (String key : resp.headers().keySet()) {
      if (key.equalsIgnoreCase(name)) {
        List<String> values = resp.headers().get(key);
        return values == null || values.isEmpty() ? null : values.get(0);
      }
    }
    return null;
  }

  static String b64(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private HttpResponse call(String method, String url, String contentType, byte[] body) {
    if (!url.startsWith(baseUrl)) {
      throw new IllegalArgumentException("URL " + url + " is not under " + baseUrl);
    }

    TestHttpRequest req = new TestHttpRequest(method).header("Host", host);
    if (contentType != null) {
      req.header("Content-Type", contentType);
    }
    req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, "/" + url.substring(baseUrl.length()));

    HttpResponse resp = responder.service(req, body, new AuditEvent("test"));
    String newNonce = header(resp, "Replay-Nonce");
    if (newNonce != null) {
      nonce = newNonce;
    }
    return resp;
  }

  private String jwkValue(String name) {
    try {
      return jwk.getString(name);
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
  }

  /** Signs with ECDSA, and converts the signature to the JWS form r || s. */
  private byte[] sign(byte[] data) throws Exception {
    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initSign(keyPair.getPrivate());
    sig.update(data);
    byte[] der = sig.sign();

    // SEQUENCE { INTEGER r, INTEGER s }, all lengths < 128
    int off = 2;
    int rLen = der[off + 1];
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(der, off + 2, off + 2 + rLen));
    off += 2 + rLen;
    int sLen = der[off + 1];
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(der, off + 2, off + 2 + sLen));

    byte[] ret = new byte[64];
    System.arraycopy(unsigned32(r), 0, ret, 0, 32);
    System.arraycopy(unsigned32(s), 0, ret, 32, 32);
    return ret;
  }

  private static byte[] unsigned32(BigInteger value) {
    byte[] bytes = value.toByteArray();
    byte[] ret = new byte[32];
    int len = Math.min(bytes.length, 32);
    System.arraycopy(bytes, bytes.length - len, ret, 32 - len, len);
    return ret;
  }

}
