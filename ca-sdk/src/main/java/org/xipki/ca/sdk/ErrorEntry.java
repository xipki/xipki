// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncodable;
import org.xipki.ca.sdk.jacob.CborEncoder;
import org.xipki.util.exception.ErrorCode;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class ErrorEntry implements CborEncodable {

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
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(2);
      encoder.writeInt(code);
      encoder.writeTextString(message);
    } catch (IOException ex) {
      throw new EncodeException("error decoding " + getClass().getName(), ex);
    }
  }

  public static ErrorEntry decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      return new ErrorEntry(
          decoder.readInt32Exact(),
          decoder.readTextString());
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + ErrorEntry.class.getName(), ex);
    }
  }

}
