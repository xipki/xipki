/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.scep.transaction;

/**
 * TODO.
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
   * PKCS #10 certificate request for update of a certificate issued by a different CA.
   * Since draft-gutman-scep version 0
   */
  UpdateReq(18),

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
