// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.ByteArrayCborDecoder;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */

public class CaNameResponse extends SdkResponse {

  private final String name;

  private final String[] aliases;

  public CaNameResponse(String name, String[] aliases) {
    this.name = name;
    this.aliases = aliases;
  }

  public String getName() {
    return name;
  }

  public String[] getAliases() {
    return aliases;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException {
    encoder.writeArrayStart(2);
    encoder.writeTextString(name);
    encoder.writeTextStrings(aliases);
  }

  public static CaNameResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      assertArrayStart("CaNameResponse", decoder, 2);
      return new CaNameResponse(
          decoder.readTextString(),
          decoder.readTextStrings());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, CaNameResponse.class), ex);
    }
  }

}
