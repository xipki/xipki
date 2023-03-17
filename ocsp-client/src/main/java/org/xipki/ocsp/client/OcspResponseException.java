// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.xipki.util.Hex;
import org.xipki.util.StringUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * Exception related to the OCSP response.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class OcspResponseException extends Exception {

  public static class InvalidResponse extends OcspResponseException {

    public InvalidResponse(String message, Throwable cause) {
      super(message, cause);
    }

    public InvalidResponse(String message) {
      super(message);
    }

  }

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

  public static class OcspTargetUnmatched extends OcspResponseException {

    public OcspTargetUnmatched(String message, Throwable cause) {
      super(message, cause);
    }

    public OcspTargetUnmatched(String message) {
      super(message);
    }

  }

  public static class ResponderUnreachable extends OcspResponseException {

    public ResponderUnreachable(String message, Throwable cause) {
      super(message, cause);
    }

    public ResponderUnreachable(String message) {
      super(message);
    }

  }

  public static class Unsuccessful extends OcspResponseException {

    private static final Map<Integer, String> codeStatusMap = new HashMap<>();

    private final int status;

    static {
      codeStatusMap.put(0, "successful");
      codeStatusMap.put(1, "malformedRequest");
      codeStatusMap.put(2, "internalError");
      codeStatusMap.put(3, "tryLater");
      codeStatusMap.put(5, "sigRequired");
      codeStatusMap.put(6, "unauthorized");
    }

    public Unsuccessful(int status) {
      super(getStatusText(status));
      this.status = status;
    }

    public int status() {
      return status;
    }

    public String statusText() {
      return getStatusText(status);
    }

    public static String getStatusText(int statusCode) {
      String status = codeStatusMap.get(statusCode);
      return (status == null) ? Integer.toString(statusCode) : status;
    }

  }

  public OcspResponseException(String message) {
    super(message);
  }

  public OcspResponseException(String message, Throwable cause) {
    super(message, cause);
  }

}
