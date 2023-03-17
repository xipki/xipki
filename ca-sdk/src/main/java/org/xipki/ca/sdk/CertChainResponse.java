// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;

/**
 * Response containing the certificate chain.
 *
 * @author Lijun Liao
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
    return JSON.parseObject(encoded, CertChainResponse.class);
  }

}
