// Copyright (c) 2013-2024 PQ Trust. All rights reserved.
// License TBD
package org.xipki.util.cbor;

import org.xipki.util.exception.EncodeException;

import java.io.IOException;

/**
 *
 * @author PQ Trust
 *
 */
public interface CborEncodable {

  void encode(CborEncoder encoder) throws IOException, EncodeException;

  default void unwrappedEncode(CborEncoder encoder) throws IOException, EncodeException {
    throw new UnsupportedOperationException("unwrappedEncode() is not supported in " + getClass().getName());
  }

  default byte[] getEncoded() throws EncodeException {
    try (ByteArrayCborEncoder encoder = new ByteArrayCborEncoder()){
      encode(encoder);
      return encoder.toByteArray();
    } catch (IOException e) {
      throw new EncodeException("IO error: " + e.getMessage());
    }
  }

  default byte[] getUnwrappedEncoded() throws EncodeException {
    try (ByteArrayCborEncoder encoder = new ByteArrayCborEncoder()){
      unwrappedEncode(encoder);
      return encoder.toByteArray();
    } catch (IOException e) {
      throw new EncodeException("IO error: " + e.getMessage());
    }
  }

}
