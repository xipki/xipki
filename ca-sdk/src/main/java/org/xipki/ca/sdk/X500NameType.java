// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.Hex;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class X500NameType {

  private transient X500Name name;

  private String text;

  private byte[] encoded;

  public X500NameType() {
  }

  public X500NameType(String text) {
    this.text = text;
  }

  public X500NameType(X500Name name) {
    try {
      this.encoded = name.getEncoded();
      this.name = name;
    } catch (IOException ex) {
      throw new IllegalStateException("error encoding X500Name " + name);
    }
  }

  public String getText() {
    return text;
  }

  public void setText(String text) {
    this.text = text;
  }

  public byte[] getEncoded() {
    return encoded;
  }

  public void setEncoded(byte[] encoded) {
    this.encoded = encoded;
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

}
