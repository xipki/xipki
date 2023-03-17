// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.transaction;

/**
 * Message type enum.
 *
 * @author Lijun Liao
 */

public enum MessageType {

  /**
   * Response to certificate or CRL request.
   */
  CertRep(3),

  /**
   * PKCS #10 certificate request for renewal of an existing certificate.
   * Since draft-gutman-scep version 0
   */
  RenewalReq(17),

  /**
   * PKCS #10 certificate request.
   */
  PKCSReq(19),

  /**
   * Certificate polling in manual enrolment.
   */
  CertPoll(20),

  /**
   * Retrieve a certificate.
   */
  GetCert(21),

  /**
   * Retrieve a CRL.
   */
  GetCRL(22);

  private final int code;

  MessageType(int code) {
    this.code = code;
  }

  public int getCode() {
    return code;
  }

  public static MessageType forValue(int code) {
    for (MessageType m : values()) {
      if (m.code == code) {
        return m;
      }
    }
    throw new IllegalArgumentException("invalid MessageType " + code);
  }

}
