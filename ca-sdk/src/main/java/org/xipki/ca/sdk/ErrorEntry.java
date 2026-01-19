// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.exception.ErrorCode;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class ErrorEntry extends SdkEncodable {

  private final int code;

  private final String message;

  public ErrorEntry(ErrorCode code, String message) {
    this.code = code.getCode();
    this.message = message;
  }

  public ErrorEntry(int code, String message) {
    this.code = code;
    this.message = message;
  }

  public int getCode() {
    return code;
  }

  public String getMessage() {
    return message;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    try {
      sb.append(ErrorCode.ofCode(code).name());
    } catch (Exception e) {
      sb.append("Unknown code ").append(code);
    }

    if (message != null) {
      sb.append(", message: ").append(message);
    }
    return sb.toString();
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(2).writeInt(code).writeTextString(message);
  }

  public static ErrorEntry decode(CborDecoder decoder) throws CodecException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      return new ErrorEntry(decoder.readInt(), decoder.readTextString());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, ErrorEntry.class), ex);
    }
  }

}
