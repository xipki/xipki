// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.cbor;

import org.xipki.util.codec.CodecException;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 *
 */
public interface CborEncodable {

  void encode(CborEncoder encoder) throws CodecException;

  default void unwrappedEncode(CborEncoder encoder)
      throws CodecException {
    throw new UnsupportedOperationException(
        "unwrappedEncode() is not supported in " + getClass().getName());
  }

  default byte[] getEncoded() throws CodecException {
    try (ByteArrayCborEncoder encoder = new ByteArrayCborEncoder()){
      encode(encoder);
      return encoder.toByteArray();
    } catch (IOException e) {
      throw new CodecException("IO error: " + e.getMessage());
    }
  }

  default byte[] getUnwrappedEncoded() throws CodecException {
    try (ByteArrayCborEncoder encoder = new ByteArrayCborEncoder()){
      unwrappedEncode(encoder);
      return encoder.toByteArray();
    } catch (IOException e) {
      throw new CodecException("IO error: " + e.getMessage());
    }
  }

}
