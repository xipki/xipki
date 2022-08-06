package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

import java.math.BigInteger;

public class GetCertRequest extends SdkRequest {

  /**
   * Serialnumber of the certificate.
   */
  private BigInteger serialNumber;

  private X500NameType issuer;

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = serialNumber;
  }

  public X500NameType getIssuer() {
    return issuer;
  }

  public void setIssuer(X500NameType issuer) {
    this.issuer = issuer;
  }

  public static GetCertRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, GetCertRequest.class);
  }

}
