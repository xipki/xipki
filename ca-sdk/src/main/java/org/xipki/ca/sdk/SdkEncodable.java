// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncodable;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public abstract class SdkEncodable implements CborEncodable {

  protected abstract void encode0(CborEncoder encoder) throws IOException, EncodeException;

  @Override
  public final void encode(CborEncoder encoder) throws EncodeException {
    try {
      encode0(encoder);
    } catch (IOException ex) {
      throw new EncodeException("IO error encoding " + getClass().getName() + ": " + ex.getMessage(), ex);
    } catch (RuntimeException ex) {
      throw new EncodeException("Runtime error encoding " + getClass().getName() + ": " + ex.getMessage(), ex);
    }
  }

  public byte[] encode() throws EncodeException {
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
      CborEncoder encoder = new CborEncoder(bout);
      encode(encoder);
      bout.flush();
      return bout.toByteArray();
    } catch (IOException ex) {
      throw new EncodeException("IOException encoding " + getClass().getName(), ex);
    }
  }

  protected static void assertArrayStart(String name, CborDecoder decoder, int size)
      throws IOException, DecodeException {
    if (decoder.readNullOrArrayLength(size)) {
      throw new DecodeException(name + " must not be null.");
    }
  }

  protected static String buildDecodeErrMessage(Exception ex, Class<?> clazz) throws DecodeException {
    return "error decoding " + clazz.getName() + ": " + ex.getMessage();
  }

}
