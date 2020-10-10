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

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

import com.alibaba.fastjson.annotation.JSONField;

/**
 * Extension PolicyConstraints.
 *
 * @author Lijun Liao
 */

public class PolicyConstraints extends ValidatableConf {

  @JSONField(ordinal = 1)
  private Integer requireExplicitPolicy;

  @JSONField(ordinal = 2)
  private Integer inhibitPolicyMapping;

  public Integer getRequireExplicitPolicy() {
    return requireExplicitPolicy;
  }

  public void setRequireExplicitPolicy(Integer requireExplicitPolicy) {
    this.requireExplicitPolicy = requireExplicitPolicy;
  }

  public Integer getInhibitPolicyMapping() {
    return inhibitPolicyMapping;
  }

  public void setInhibitPolicyMapping(Integer inhibitPolicyMapping) {
    this.inhibitPolicyMapping = inhibitPolicyMapping;
  }

  @Override
  public void validate()
      throws InvalidConfException {
    // Only for CA, at least one of requireExplicitPolicy and inhibitPolicyMapping must be present
    if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
      throw new InvalidConfException(
          "requireExplicitPolicy and inhibitPolicyMapping may not be both null");
    }
  }

  public ASN1Sequence toXiPolicyConstrains()
      throws CertprofileException {
    if (requireExplicitPolicy != null && requireExplicitPolicy < 0) {
      throw new CertprofileException(
          "negative requireExplicitPolicy is not allowed: " + requireExplicitPolicy);
    }

    if (inhibitPolicyMapping != null && inhibitPolicyMapping < 0) {
      throw new CertprofileException(
          "negative inhibitPolicyMapping is not allowed: " + inhibitPolicyMapping);
    }

    if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
      return null;
    }

    final boolean explicit = false;
    ASN1EncodableVector vec = new ASN1EncodableVector();
    if (requireExplicitPolicy != null) {
      vec.add(new DERTaggedObject(explicit, 0,
          new ASN1Integer(BigInteger.valueOf(requireExplicitPolicy))));
    }

    if (inhibitPolicyMapping != null) {
      vec.add(new DERTaggedObject(explicit, 1,
          new ASN1Integer(BigInteger.valueOf(inhibitPolicyMapping))));
    }

    return new DERSequence(vec);
  } //method toXiPolicyConstrains

} // class PolicyConstraints
