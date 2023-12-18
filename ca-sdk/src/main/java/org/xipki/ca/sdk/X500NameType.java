// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.Args;
import org.xipki.util.Hex;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class X500NameType extends SdkEncodable {

  private X500Name name;

  private final String text;

  private final byte[] encoded;

  public X500NameType(String text) {
    this.text = Args.notBlank(text, "text");
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

    try {
      name = (encoded != null) ? X500Name.getInstance(encoded) : new X500Name(text);
      return name;
    } catch (Exception e) {
      throw new IOException("error parsing X500Name " + (text != null ? text : "0x" + Hex.encode(encoded)));
    }
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeArrayStart(2);
    encoder.writeTextString(encoded == null ? text : null);
    encoder.writeByteString(encoded);
  }

  public static X500NameType decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(2)) {
        return null;
      }

      String text = decoder.readTextString();
      byte[] encoded = decoder.readByteString();
      if ((text == null) == (encoded == null)) {
        throw new DecodeException("exactly one of text and encoded shall be non-null");
      }

      if (text != null) {
        return new X500NameType(text);
      } else {
        return new X500NameType(encoded);
      }
    } catch (IOException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, X500NameType.class), ex);
    }
  }

}
