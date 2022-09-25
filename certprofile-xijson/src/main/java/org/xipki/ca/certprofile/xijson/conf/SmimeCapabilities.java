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
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableBinary;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

/**
 * Extension S/MIME Capabilities.
 *
 * @author Lijun Liao
 */

public class SmimeCapabilities extends ValidatableConf {

  public static class SmimeCapability extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableOid capabilityId;

    @JSONField(ordinal = 2)
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

  public static class SmimeCapabilityParameter extends ValidatableConf {

    @JSONField(ordinal = 1)
    private BigInteger integer;

    @JSONField(ordinal = 2)
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
