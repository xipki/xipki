// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 *
 * @author Lijun Liao (xipki)
 */

public class CaNameResponse extends SdkResponse {

  private final String name;

  private final String[] aliases;

  public CaNameResponse(String name, String[] aliases) {
    this.name = name;
    this.aliases = aliases;
  }

  public String name() {
    return name;
  }

  public String[] aliases() {
    return aliases;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(2).writeTextString(name)
        .writeTextStrings(aliases);
  }

  public static CaNameResponse decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new CborDecoder(encoded)) {
      assertArrayStart("CaNameResponse", decoder, 2);
      return new CaNameResponse(
          decoder.readTextString(), decoder.readTextStrings());
    } catch (RuntimeException ex) {
      throw new CodecException(
          buildDecodeErrMessage(ex, CaNameResponse.class), ex);
    }
  }

}
