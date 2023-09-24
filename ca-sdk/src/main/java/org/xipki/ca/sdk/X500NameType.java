// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.sdk.jacob.CborDecoder;
import org.xipki.ca.sdk.jacob.CborEncodable;
import org.xipki.ca.sdk.jacob.CborEncoder;
import org.xipki.util.Hex;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class X500NameType implements CborEncodable {

  private X500Name name;

  private final String text;

  private final byte[] encoded;

  public X500NameType(String text) {
    this.text = text;
    this.encoded = null;
  }

  public X500NameType(X500Name name) {
    try {
      this.encoded = name.getEncoded();
      this.name = name;
      this.text = null;
    } catch (IllegalArgumentException | IOException ex) {
      throw new IllegalStateException("error encoding X500Name " + name);
    }
  }

  public X500NameType(byte[] encoded) {
    try {
      this.encoded = encoded;
      this.name = X500Name.getInstance(encoded);
      this.text = null;
    } catch (IllegalArgumentException ex) {
      throw new IllegalStateException("error encoding X500Name " + name);
    }
  }

  public String getText() {
    return text;
  }

  public byte[] getEncoded() {
    return encoded;
  }

  public X500Name toX500Name() throws IOException {
    if (name != null) {
      return name;
    }

    if (text == null && encoded == null) {
      return null;
    }

    try {
      name = (encoded != null) ? X500Name.getInstance(encoded) : new X500Name(text);
      return name;
    } catch (Exception e) {
      throw new IOException("error parsing X500Name " + (text != null ? text : "0x" + Hex.encode(encoded)));
    }
  }

  @Override
  public void encode(CborEncoder encoder) throws EncodeException {
    try {
      encoder.writeArrayStart(2);
      encoder.writeTextString(text);
      encoder.writeByteString(encoded);
    } catch (IOException ex) {
      throw new EncodeException("error encoding " + getClass().getName(), ex);
    }
  }

  public static X500NameType decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      String text = decoder.readTextString();
      byte[] encoded = decoder.readByteString();

      if (text != null) {
        return new X500NameType(text);
      } else {
        return new X500NameType(encoded);
      }
    } catch (IOException ex) {
      throw new DecodeException("error decoding " + X500NameType.class.getName(), ex);
    }
  }

}
