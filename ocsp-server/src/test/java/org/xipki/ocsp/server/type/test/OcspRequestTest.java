// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.ocsp.server.type.EncodingException;
import org.xipki.ocsp.server.type.OcspRequest;

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

}
