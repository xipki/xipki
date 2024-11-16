package org.xipki.util.cbor;

import org.xipki.util.exception.EncodeException;

import java.io.IOException;

public class CborTaggedObject implements CborEncodable {

  private final long tag;

  private final Object value;

  public CborTaggedObject(long tag, Object value) {
    this.tag = tag;
    this.value = value;
  }

  @Override
  public void encode(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeTag(tag);
    unwrappedEncode(encoder);
  }

  @Override
  public void unwrappedEncode(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeAnyObject(value);
  }
}
