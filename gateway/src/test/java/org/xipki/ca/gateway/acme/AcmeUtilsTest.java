// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.Functions;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * JUnit test case of {@link AcmeUtils}.
 * @author Lijun Liao (xipki)
 */
public class AcmeUtilsTest {

  @Test
  public void jwkThumbprint() {
    // RFC 7638, Section 3.1
    Map<String, String> jwk = new HashMap<>();
    jwk.put("kty", "RSA");
    jwk.put("n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhW" +
        "x4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3o" +
        "knjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65" +
        "YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL" +
        "5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRw" +
        "r3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
    jwk.put("e", "AQAB");
    // optional members are not part of the thumbprint.
    jwk.put("alg", "RS256");
    jwk.put("kid", "2011-04-29");

    Assert.assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", AcmeUtils.jwkSha256(jwk));

    // values which would change the JSON structure
    jwk.put("e", "AQAB\",\"x\":\"y");
    Assert.assertThrows(IllegalArgumentException.class, () -> AcmeUtils.jwkSha256(jwk));
    jwk.put("e", "AQ\\AB");
    Assert.assertThrows(IllegalArgumentException.class, () -> AcmeUtils.jwkSha256(jwk));
  }

  @Test
  public void ecdsaJwsSignature() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
    kpGen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair kp = kpGen.generateKeyPair();

    Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
    ECPublicKey pubKey = (ECPublicKey) kp.getPublic();
    Map<String, String> jwk = new HashMap<>();
    jwk.put("kty", "EC");
    jwk.put("crv", "P-256");
    jwk.put("x", b64.encodeToString(toBytes(pubKey.getW().getAffineX(), 32)));
    jwk.put("y", b64.encodeToString(toBytes(pubKey.getW().getAffineY(), 32)));

    byte[] data = "protected.payload".getBytes();
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(kp.getPrivate());
    signer.update(data);
    // JWS signature: R || S
    byte[] jwsSig = Functions.dsaSigX962ToPlain(signer.sign(), 32);

    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(AcmeUtils.jwkPublicKey(jwk));
    verifier.update(data);
    Assert.assertTrue(verifier.verify(AcmeUtils.ecdsaJwsSigToDer(jwsSig, 32)));

    Assert.assertThrows(AcmeProtocolException.class,
        () -> AcmeUtils.ecdsaJwsSigToDer(new byte[63], 32));
  }

  @Test
  public void decodeBase64Url() {
    Assert.assertNull(AcmeUtils.decodeBase64UrlOrNull("ab+/"));
    Assert.assertNull(AcmeUtils.decodeBase64UrlOrNull("Āabc"));
    Assert.assertThrows(AcmeProtocolException.class,
        () -> AcmeUtils.decodeBase64Url(null, "payload"));
    Assert.assertThrows(AcmeProtocolException.class,
        () -> AcmeUtils.decodeBase64Url("a", "payload"));
  }

  private static byte[] toBytes(BigInteger bn, int len) {
    byte[] bytes = bn.toByteArray();
    byte[] res = new byte[len];
    if (bytes.length > len) {
      System.arraycopy(bytes, bytes.length - len, res, 0, len);
    } else {
      System.arraycopy(bytes, 0, res, len - bytes.length, bytes.length);
    }
    return res;
  }

}
