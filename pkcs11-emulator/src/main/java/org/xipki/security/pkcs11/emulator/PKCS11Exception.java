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

package org.xipki.security.pkcs11.emulator;

import iaik.pkcs.pkcs11.constants.Functions;

/**
 * TODO.
 * @author Lijun Liao
 * @since 4.0.0
 */

// CHECKSTYLE:SKIP
public class PKCS11Exception extends Exception {

  private static final long serialVersionUID = -5193259612747392211L;

  /**
   * The code of the error which was the reason for this exception.
   */
  private long errorCode;

  private String errorDescription;

  /**
   * Constructor taking the error code as defined for the CKR_* constants
   * in PKCS#11.
   *
   * @param errorCode
   *          The PKCS#11 error code (return value).
   */
  public PKCS11Exception(long errorCode) {
    this.errorCode = errorCode;
    this.errorDescription = Functions.errorCodeToString(errorCode);
  }

  /**
   * This method gets the corresponding text error message from
   * a property file. If this file is not available, it returns the error
   * code as a hex-string.
   *
   * @return The message or the error code; e.g. "CKR_DEVICE_ERROR" or
   *         "0x00000030".
   * @preconditions
   * @postconditions (result <> null)
   */
  public String getMessage() {
    return errorDescription;
  }

  /**
   * Returns the PKCS#11 error code.
   *
   * @return The error code; e.g. 0x00000030.
   */
  public long getErrorCode() {
    return errorCode;
  }

}
