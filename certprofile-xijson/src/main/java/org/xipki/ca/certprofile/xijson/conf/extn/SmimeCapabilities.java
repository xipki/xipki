// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableBinary;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

/**
 * Extension S/MIME Capabilities.
 *
 * @author Lijun Liao (xipki)
 */

public class SmimeCapabilities extends ValidableConf {

  public static class SmimeCapability extends ValidableConf {

    private DescribableOid capabilityId;

    private SmimeCapabilityParameter parameter;

    public DescribableOid getCapabilityId() {
      return capabilityId;
    }

    public void setCapabilityId(DescribableOid capabilityId) {
      this.capabilityId = capabilityId;
    }

    public SmimeCapabilityParameter getParameter() {
      return parameter;
    }

    public void setParameter(SmimeCapabilityParameter parameter) {
      this.parameter = parameter;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(capabilityId, "capabilityId");
      validate(capabilityId, parameter);
    }

  } // class SmimeCapability

  public static class SmimeCapabilityParameter extends ValidableConf {

    private BigInteger integer;

    private DescribableBinary binary;

    public BigInteger getInteger() {
      return integer;
    }

    public void setInteger(BigInteger integer) {
      this.integer = integer;
    }

    public DescribableBinary getBinary() {
      return binary;
    }

    public void setBinary(DescribableBinary binary) {
      this.binary = binary;
    }

    @Override
    public void validate() throws InvalidConfException {
      exactOne(integer, "integer", binary, "binary");
      validate(binary);
    }

  } // class SmimeCapabilityParameter

  private List<SmimeCapability> capabilities;

  public List<SmimeCapability> getCapabilities() {
    if (capabilities == null) {
      capabilities = new LinkedList<>();
    }
    return capabilities;
  }

  public void setCapabilities(List<SmimeCapability> capabilities) {
    this.capabilities = capabilities;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(capabilities, "capabilities");
    validate(capabilities);
  }

} // class SmimeCapabilities
