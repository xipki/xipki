// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

/**
 * Response containing the certificate chain.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CertChainResponse extends SdkResponse {

  private byte[][] certificates;

  public byte[][] getCertificates() {
    return certificates;
  }

  public void setCertificates(byte[][] certificates) {
    this.certificates = certificates;
  }

  public static CertChainResponse decode(byte[] encoded) {
    return CBOR.parseObject(encoded, CertChainResponse.class);
  }

}
