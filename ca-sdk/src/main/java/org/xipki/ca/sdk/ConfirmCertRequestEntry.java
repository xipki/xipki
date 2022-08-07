package org.xipki.ca.sdk;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class ConfirmCertRequestEntry {

  private BigInteger certReqId;

  /**
   * certHash.
   */
  private byte[] certhash;

  private boolean accept;

  public BigInteger getCertReqId() {
    return certReqId;
  }

  public void setCertReqId(BigInteger certReqId) {
    this.certReqId = certReqId;
  }

  public byte[] getCerthash() {
    return certhash;
  }

  public void setCerthash(byte[] certhash) {
    this.certhash = certhash;
  }

  public boolean isAccept() {
    return accept;
  }

  public void setAccept(boolean accept) {
    this.accept = accept;
  }

}
