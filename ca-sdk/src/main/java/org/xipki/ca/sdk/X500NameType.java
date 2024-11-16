// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.Args;
import org.xipki.util.Hex;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.cbor.CborType;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class X500NameType extends SdkEncodable {

  private static final long TAG_ENCODED = 1;

  private static final long TAG_TEXT = 2;

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
      throw new IOException("error parsing X500Name " + (encoded == null ? text : "0x" + Hex.encode(encoded)));
    }
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    if (encoded != null) {
      encoder.writeTag(TAG_ENCODED);
      encoder.writeByteString(encoded);
    } else {
      encoder.writeTag(TAG_TEXT);
      encoder.writeTextString(text);
    }
  }

  public static X500NameType decode(CborDecoder decoder) throws DecodeException {
    CborType type = decoder.peekType();
    if (CborDecoder.isNull(type)) {
      decoder.readNull();
      return null;
    }

    long tag = decoder.readTag();
    if (tag == TAG_ENCODED) {
      return new X500NameType(decoder.readByteString());
    } else {
      return new X500NameType(decoder.readTextString());
    }
  }

}
