// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.xipki.pkix.asn1.ocsp.OCSPResponseStatus;
import org.xipki.codec.Hex;
import org.xipki.pkix.util.misc.StringUtil;

/**
 * OCSP Response Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class OcspResponseException extends Exception {

  /**
   * Invalid Response payload.
   */
  public static class InvalidResponse extends OcspResponseException {

    public InvalidResponse(String message, Throwable cause) {
      super(message, cause);
    }

    public InvalidResponse(String message) {
      super(message);
    }

  }

  /**
   * OCSP Nonce Unmatched.
   */
  public static class OcspNonceUnmatched extends OcspResponseException {

    public OcspNonceUnmatched(byte[] expected, byte[] is) {
      super(buildMessage(expected, is));
    }

    private static String buildMessage(byte[] expected, byte[] is) {
      return StringUtil.concat("nonce unmatch (received ",
          (is == null || is.length == 0 ? "none" : Hex.encode(is)), ", but expected ",
          (expected == null || expected.length == 0 ? "none" : Hex.encode(expected)), ")");
    }

  }

  /**
   * OCSP Target Unmatched.
   */
  public static class OcspTargetUnmatched extends OcspResponseException {

    public OcspTargetUnmatched(String message, Throwable cause) {
      super(message, cause);
    }

    public OcspTargetUnmatched(String message) {
      super(message);
    }

  }

  /**
   * Responder Unreachable.
   */
  public static class ResponderUnreachable extends OcspResponseException {

    public ResponderUnreachable(String message, Throwable cause) {
      super(message, cause);
    }

    public ResponderUnreachable(String message) {
      super(message);
    }

  }

  /**
   * Unsuccessful.
   */
  public static class Unsuccessful extends OcspResponseException {

    private final OCSPResponseStatus status;

    public Unsuccessful(OCSPResponseStatus status) {
      super(status.getEnumeratedName());
      this.status = status;
    }

    public OCSPResponseStatus status() {
      return status;
    }

  }

  public OcspResponseException(String message) {
    super(message);
  }

  public OcspResponseException(String message, Throwable cause) {
    super(message, cause);
  }

}
