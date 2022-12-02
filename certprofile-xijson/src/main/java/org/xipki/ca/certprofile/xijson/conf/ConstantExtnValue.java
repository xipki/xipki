/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.xipki.util.Base64;
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
