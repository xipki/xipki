// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkix.asn1.ocsp.OCSPRequest;
import org.xipki.codec.Hex;
import org.xipki.ocsp.server.type.EncodingException;
import org.xipki.ocsp.server.type.ExtendedExtension;
import org.xipki.ocsp.server.type.OID;
import org.xipki.ocsp.server.type.OcspRequest;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

/**
 * JUnit test case of parsing malformed OCSP requests.
 * @author Lijun Liao (xipki)
 */
public class OcspRequestTest {

  private static final String[] TRUNCATED_REQUESTS = {
      "",
      "30",
      "3003",
      "300330",
      "3084",
      "30847fffffff",
      "3084ffffffff30",
      "3003300130",
      "30823000",
  };

  private static final String[] INVALID_REQUESTS = {
      // empty requestList
      "300430023000",
      // CertID without serialNumber
      "300e300c300a3008300606052b0e03021a",
  };

  // Unsigned request with nonce (16 bytes) and the unknown non-critical extension 1.2.3.4.
  private static final String REQUEST_WITH_UNKNOWN_EXTENSION =
      "30733071303f303d303b300906052b0e03021a050004141111111111111111111111111111111111111111" +
      "0414222222222222222222222222222222222222222202020123a22e302c301f06092b0601050507300102" +
      "0412041033333333333333333333333333333333300906032a030404020500";

  private static final byte[] HASH_ALGO = Hex.decode("300906052b0e03021a0500");

  private static final byte[] NAME_HASH = der(0x04, new byte[20]);

  private static final byte[] KEY_HASH = der(0x04, new byte[20]);

  private static final byte[] SERIAL = Hex.decode("02020123");

  private static final byte[] CERT_ID = der(0x30, HASH_ALGO, NAME_HASH, KEY_HASH, SERIAL);

  private static final byte[] NONCE_OID = Hex.decode("06092b0601050507300102");

  private static byte[] der(int tag, byte[]... parts) {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    for (byte[] part : parts) {
      body.writeBytes(part);
    }

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(tag);
    if (body.size() > 0xFF) {
      out.write(0x82);
      out.write(body.size() >> 8);
    } else if (body.size() > 0x7F) {
      out.write(0x81);
    }
    out.write(body.size());
    out.writeBytes(body.toByteArray());
    return out.toByteArray();
  }

  /**
   * Returns the OCSPRequest with one Request of the given CertID.
   */
  private static byte[] request(byte[] certId) {
    return der(0x30, der(0x30, der(0x30, der(0x30, certId))));
  }

  private static byte[] requestWithExtension(byte[] extension) {
    return der(0x30, der(0x30, der(0x30, der(0x30, CERT_ID)),
        der(0xA2, der(0x30, extension))));
  }

  private static byte[] certId(byte[] serial) {
    return der(0x30, HASH_ALGO, NAME_HASH, KEY_HASH, serial);
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] rv = new byte[a.length + b.length];
    System.arraycopy(a, 0, rv, 0, a.length);
    System.arraycopy(b, 0, rv, a.length, b.length);
    return rv;
  }

  private static void assertRejected(String name, byte[] request) {
    Assert.assertThrows(name, EncodingException.class, () -> OcspRequest.getInstance(request));
  }

  @Test
  public void validRequests() throws Exception {
    Assert.assertEquals(BigInteger.valueOf(0x123),
        OcspRequest.getInstance(request(CERT_ID)).requestList().get(0).serialNumber());

    // serial number 0 is allowed.
    Assert.assertEquals(BigInteger.ZERO, OcspRequest.getInstance(
        request(certId(Hex.decode("020100")))).requestList().get(0).serialNumber());

    // version, requestorName, singleRequestExtensions and optionalSignature
    byte[] singleRequest = der(0x30, CERT_ID, der(0xA0, der(0x30)));
    byte[] tbs = der(0x30, Hex.decode("a003020100"), der(0xA1, der(0x82, new byte[1])),
        der(0x30, singleRequest));
    byte[] signedRequest = der(0x30, tbs, der(0xA0, der(0x30)));
    Assert.assertEquals(1, OcspRequest.getInstance(signedRequest).requestList().size());
    Assert.assertTrue(OcspRequest.containsSignature(signedRequest));
    Assert.assertFalse(OcspRequest.containsSignature(request(CERT_ID)));
  }

  @Test
  public void negativeSerialIsRejected() {
    assertRejected("negative serial", request(certId(Hex.decode("0201ff"))));
  }

  @Test
  public void wrongTagsAreRejected() {
    assertRejected("serial", request(certId(Hex.decode("04020123"))));
    assertRejected("nameHash", request(der(0x30, HASH_ALGO, der(0x0C, new byte[20]),
        KEY_HASH, SERIAL)));
    assertRejected("keyHash", request(der(0x30, HASH_ALGO, NAME_HASH,
        der(0x0C, new byte[20]), SERIAL)));
    assertRejected("hashAlgorithm", request(der(0x31, HASH_ALGO, NAME_HASH, KEY_HASH, SERIAL)));
    assertRejected("OCSPRequest", der(0x70, der(0x30, der(0x30, der(0x30, CERT_ID)))));
    assertRejected("TBSRequest", der(0x30, der(0x70, der(0x30, der(0x30, CERT_ID)))));
    assertRejected("requestList", der(0x30, der(0x30, der(0x31, der(0x30, CERT_ID)))));
    assertRejected("Request", der(0x30, der(0x30, der(0x30, der(0x31, CERT_ID)))));
    assertRejected("requestExtensions", der(0x30, der(0x30, der(0x30, der(0x30, CERT_ID)),
        der(0xA1, der(0x30)))));
    assertRejected("extnId", requestWithExtension(der(0x30, Hex.decode("0c0141"),
        der(0x04, der(0x04, new byte[8])))));
    assertRejected("extnValue", requestWithExtension(der(0x30, NONCE_OID,
        der(0x0C, der(0x04, new byte[8])))));
  }

  @Test
  public void unexpectedFieldsAreRejected() {
    byte[] nullObject = Hex.decode("0500");
    assertRejected("CertID", request(der(0x30, HASH_ALGO, NAME_HASH, KEY_HASH, SERIAL,
        nullObject)));
    assertRejected("Request", der(0x30, der(0x30, der(0x30, der(0x30, CERT_ID, nullObject)))));
    assertRejected("TBSRequest", der(0x30, der(0x30, der(0x30, der(0x30, CERT_ID)), nullObject)));
    assertRejected("Extension", requestWithExtension(der(0x30, NONCE_OID,
        der(0x04, der(0x04, new byte[8])), nullObject)));
  }

  @Test
  public void trailingDataIsRejected() throws Exception {
    byte[] request = concat(request(CERT_ID), Hex.decode("0500"));
    assertRejected("after OCSPRequest", request);
    // the trailing data is not the optionalSignature.
    Assert.assertFalse(OcspRequest.containsSignature(request));
    assertRejected("after optionalSignature",
        der(0x30, der(0x30, der(0x30, der(0x30, CERT_ID))), der(0xA0, der(0x30)),
            Hex.decode("0500")));
  }

  @Test
  public void childMustNotExceedItsParent() {
    byte[] singleRequest = der(0x30, CERT_ID);
    byte[] request = der(0x30, der(0x30, der(0x30, singleRequest, singleRequest)));
    // increase the length of the CertID in the first Request by 1
    int offset = request.length - 2 * singleRequest.length + 2 + 1;
    request[offset]++;
    assertRejected("CertID exceeds Request", request);
  }

  @Test
  public void nonceLength() throws Exception {
    for (int len : new int[]{0, 1, 16, 32, 200}) {
      byte[] value = der(0x04, new byte[len]);
      ExtendedExtension extn = OcspRequest.getInstance(requestWithExtension(
          der(0x30, NONCE_OID, der(0x04, value)))).extensions().get(0);
      Assert.assertEquals(len, extn.octetStringLengthOfExtnValue());
      Assert.assertEquals(value.length, extn.extnValueLength());
    }
  }

  @Test
  public void invalidNonceIsRejected() throws Exception {
    byte[][] values = {
        new byte[0],
        der(0x0C, new byte[8]),                      // not an OCTET STRING
        concat(der(0x04, new byte[8]), new byte[1]), // trailing data
        Hex.decode("040801")                         // truncated
    };

    for (byte[] value : values) {
      ExtendedExtension extn = OcspRequest.getInstance(requestWithExtension(
          der(0x30, NONCE_OID, der(0x04, value)))).extensions().get(0);
      Assert.assertThrows(Hex.encode(value), EncodingException.class,
          extn::octetStringLengthOfExtnValue);
    }
  }

  @Test
  public void truncatedRequests() {
    for (String hex : TRUNCATED_REQUESTS) {
      byte[] request = Hex.decode(hex);
      Assert.assertThrows("readRequestVersion " + hex, EncodingException.class,
          () -> OcspRequest.readRequestVersion(request));
      Assert.assertThrows("getInstance " + hex, EncodingException.class,
          () -> OcspRequest.getInstance(request));
    }
  }

  @Test
  public void invalidRequests() {
    for (String hex : INVALID_REQUESTS) {
      byte[] request = Hex.decode(hex);
      Assert.assertThrows("getInstance " + hex, EncodingException.class,
          () -> OcspRequest.getInstance(request));
    }
  }

  @Test
  public void unknownNonCriticalExtensionIsIgnored() throws Exception {
    byte[] request = Hex.decode(REQUEST_WITH_UNKNOWN_EXTENSION);
    // the first parser is used for unsigned requests, the second one for signed requests.
    OcspRequest[] reqs = {OcspRequest.getInstance(request),
        OcspRequest.getInstance(OCSPRequest.fromEncoded(request))};

    for (OcspRequest req : reqs) {
      Assert.assertEquals(1, req.requestList().size());
      Assert.assertEquals(BigInteger.valueOf(0x123), req.requestList().get(0).serialNumber());
      Assert.assertEquals(1, req.extensions().size());
      ExtendedExtension extn = req.extensions().get(0);
      Assert.assertNotNull(extn);
      Assert.assertSame(OID.ID_PKIX_OCSP_NONCE, extn.extnType());
      Assert.assertEquals(18, extn.extnValueLength());
    }
  }

}
