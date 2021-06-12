/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import com.alibaba.fastjson.annotation.JSONField;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * Configuration with description.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class Describable extends ValidatableConf {

  @JSONField(ordinal = 2)
  private String description;

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public static class DescribableOid extends Describable {

    @JSONField(ordinal = 1)
    private String oid;

    public String getOid() {
      return oid;
    }

    public void setOid(String oid) {
      this.oid = oid;
    }

    public ASN1ObjectIdentifier toXiOid() {
      return new ASN1ObjectIdentifier(oid);
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notBlank(oid, "oid");
      try {
        toXiOid();
      } catch (Exception ex) {
        throw new InvalidConfException("invalid oid " + oid);
      }
    }

  } // class DescribableOid

  public static class DescribableInt extends Describable {

    @JSONField(ordinal = 1)
    private int value;

    /**
     * Gets the value of the value property.
     * @return the value of the value property.
     */
    public int getValue() {
      return value;
    }

    public void setValue(int value) {
      this.value = value;
    }

    @Override
    public void validate()
        throws InvalidConfException {
    }
  } // class DescribableInt

  public static class DescribableString extends Describable {

    @JSONField(ordinal = 1)
    private String value;

    @Override
    public void validate()
        throws InvalidConfException {
      notNull(value, "value");
    }

  } // class DescribableString

  public static class DescribableBinary extends Describable {

    @JSONField(ordinal = 1)
    private byte[] value;

    public byte[] getValue() {
      return value;
    }

    public void setValue(byte[] value) {
      this.value = value;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notNull(value, "value");
    }

  } // class DescribableBinary

}
