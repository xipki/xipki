// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class EnrollOrPullCertResponseEntry {

  private BigInteger id;

  private ErrorEntry error;

  private byte[] cert;

  private byte[] privateKey;

  public BigInteger getId() {
    return id;
  }

  public void setId(BigInteger id) {
    this.id = id;
  }

  public ErrorEntry getError() {
    return error;
  }

  public void setError(ErrorEntry error) {
    this.error = error;
  }

  public byte[] getCert() {
    return cert;
  }

  public void setCert(byte[] cert) {
    this.cert = cert;
  }

  public byte[] getPrivateKey() {
    return privateKey;
  }

  public void setPrivateKey(byte[] privateKey) {
    this.privateKey = privateKey;
  }
}
