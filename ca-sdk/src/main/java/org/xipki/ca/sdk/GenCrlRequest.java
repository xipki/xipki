// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * Gen CRLRequest payload.
 *
 * @author Lijun Liao (xipki)
 */
public class GenCrlRequest extends SdkRequest {

  /**
   * Returns CRL published under this CRL distribution point.
   */
  private final String crlDp;

  public GenCrlRequest(String crlDp) {
    this.crlDp = crlDp;
  }

  public String crlDp() {
    return crlDp;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    int start = buf.length();
    appendField(buf, indentLevel, "crlDp", crlDp);

    return endToString(buf, indentLevel, start);
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(1).writeTextString(crlDp);
  }

  public static GenCrlRequest decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("GenCrlRequest", decoder, 1);
      return new GenCrlRequest(decoder.readTextString());
    } catch (RuntimeException ex) {
      throw new CodecException(buildDecodeErrMessage(ex, GenCrlRequest.class), ex);
    }
  }

}
