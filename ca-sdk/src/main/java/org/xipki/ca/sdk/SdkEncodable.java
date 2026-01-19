// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborEncoder;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncodable;
import org.xipki.util.codec.cbor.CborEncoder;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public abstract class SdkEncodable implements CborEncodable {

  protected abstract void encode0(CborEncoder encoder)
      throws CodecException;

  @Override
  public final void encode(CborEncoder encoder) throws CodecException {
    encode0(encoder);
  }

  public byte[] encode() throws CodecException {
    ByteArrayCborEncoder encoder = new ByteArrayCborEncoder();
    encode(encoder);
    return encoder.toByteArray();
  }

  protected static void assertArrayStart(
      String name, CborDecoder decoder, int size)
      throws CodecException {
    if (decoder.readNullOrArrayLength(size)) {
      throw new CodecException(name + " must not be null.");
    }
  }

  protected static String buildDecodeErrMessage(Exception ex, Class<?> clazz)
      throws CodecException {
    return "error decoding " + clazz.getName() + ": " + ex.getMessage();
  }

}
