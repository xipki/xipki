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

import java.util.LinkedList;
import java.util.List;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

import com.alibaba.fastjson.annotation.JSONField;

/**
 * Configuration of the extension CertificatePolicies.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertificatePolicyInformationType extends ValidatableConf {

  @JSONField(ordinal = 1)
  private DescribableOid policyIdentifier;

  @JSONField(ordinal = 2)
  private List<PolicyQualifier> policyQualifiers;

  public DescribableOid getPolicyIdentifier() {
    return policyIdentifier;
  }

  public void setPolicyIdentifier(DescribableOid policyIdentifier) {
    this.policyIdentifier = policyIdentifier;
  }

  public List<PolicyQualifier> getPolicyQualifiers() {
    if (policyQualifiers == null) {
      policyQualifiers = new LinkedList<>();
    }
    return policyQualifiers;
  }

  public void setPolicyQualifiers(List<PolicyQualifier> policyQualifiers) {
    this.policyQualifiers = policyQualifiers;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(policyIdentifier, "policyIdentifier");
    validate(policyIdentifier);
    validate(policyQualifiers);
  }

  public static enum PolicyQualfierType {
    cpsUri,
    userNotice
  } // class PolicyQualfierType

  public static class PolicyQualifier extends ValidatableConf {

    private PolicyQualfierType type;

    private String value;

    public PolicyQualfierType getType() {
      return type;
    }

    public void setType(PolicyQualfierType type) {
      this.type = type;
    }

    public String getValue() {
      return value;
    }

    public void setValue(String value) {
      this.value = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(type, "type");
      notEmpty(value, "value");
    }

  } // class PolicyQualifier
}
