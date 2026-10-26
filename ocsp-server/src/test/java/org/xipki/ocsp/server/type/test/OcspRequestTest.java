// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.ocsp.server.type.EncodingException;
import org.xipki.ocsp.server.type.ExtendedExtension;
import org.xipki.ocsp.server.type.OID;
import org.xipki.ocsp.server.type.OcspRequest;
import org.xipki.pkix.asn1.ocsp.OCSPRequest;

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
