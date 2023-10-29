// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.ByteArrayCborDecoder;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

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
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(2);
      encoder.writeTextString(name);
      encoder.writeTextStrings(aliases);
    } catch (IOException | RuntimeException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static CaNameResponse decode(byte[] encoded) throws DecodeException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)){
      if (decoder.readNullOrArrayLength(2)) {
        throw new DecodeException("CaNameResponse could not be null.");
      }

      return new CaNameResponse(
          decoder.readTextString(),
          decoder.readTextStrings());
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException("error decoding " + CaNameResponse.class.getName(), ex);
    }
  }

}
