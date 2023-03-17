// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Configuration with description.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class Describable extends ValidatableConf {

  private String description;

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public static class DescribableOid extends Describable {

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
    public void validate() throws InvalidConfException {
      notBlank(oid, "oid");
      try {
        toXiOid();
      } catch (Exception ex) {
        throw new InvalidConfException("invalid oid " + oid);
      }
    }

  } // class DescribableOid

  public static class DescribableInt extends Describable {

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
    public void validate() throws InvalidConfException {
    }
  } // class DescribableInt

  public static class DescribableBinary extends Describable {

    private byte[] value;

    public byte[] getValue() {
      return value;
    }

    public void setValue(byte[] value) {
      this.value = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(value, "value");
    }

  } // class DescribableBinary

}
