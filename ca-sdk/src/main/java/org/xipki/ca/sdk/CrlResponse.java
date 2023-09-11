// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

/**
 * Response containing the CRL.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CrlResponse extends SdkResponse {

  private byte[] crl;

  public byte[] getCrl() {
    return crl;
  }

  public void setCrl(byte[] crl) {
    this.crl = crl;
  }

  public static CrlResponse decode(byte[] encoded) {
    return CBOR.parseObject(encoded, CrlResponse.class);
  }

}
