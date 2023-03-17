// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;

/**
 * Configure extension with given (constant) extension value.
 * @author Lijun Liao
 */
public class ConstantExtnValue extends ValidatableConf {

  private byte[] value;

  public byte[] getValue() {
    return value;
  }

  public void setValue(byte[] value) {
    this.value = value;
  }

  public ASN1Encodable toASN1Encodable() throws InvalidConfException {
    ASN1StreamParser parser = new ASN1StreamParser(value);
    try {
      return parser.readObject();
    } catch (IOException ex) {
      throw new InvalidConfException("could not parse the constant extension value", ex);
    }
  }

  @Override
  public void validate() throws InvalidConfException {
    if (value == null) {
      throw new InvalidConfException("value may not be non-null");
    }
  }

}
