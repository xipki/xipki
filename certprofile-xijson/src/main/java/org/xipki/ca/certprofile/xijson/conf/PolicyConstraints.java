// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.*;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.math.BigInteger;

/**
 * Extension PolicyConstraints.
 *
 * @author Lijun Liao (xipki)
 */

public class PolicyConstraints extends ValidableConf {

  private Integer requireExplicitPolicy;

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
  public void validate() throws InvalidConfException {
    // Only for CA, at least one of requireExplicitPolicy and inhibitPolicyMapping must be present
    if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
      throw new InvalidConfException("requireExplicitPolicy and inhibitPolicyMapping may not be both null");
    }
  }

  public ASN1Sequence toXiPolicyConstraints() throws CertprofileException {
    if (requireExplicitPolicy != null && requireExplicitPolicy < 0) {
      throw new CertprofileException("negative requireExplicitPolicy is not allowed: " + requireExplicitPolicy);
    }

    if (inhibitPolicyMapping != null && inhibitPolicyMapping < 0) {
      throw new CertprofileException("negative inhibitPolicyMapping is not allowed: " + inhibitPolicyMapping);
    }

    if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
      return null;
    }

    final boolean explicit = false;
    ASN1EncodableVector vec = new ASN1EncodableVector();
    if (requireExplicitPolicy != null) {
      vec.add(new DERTaggedObject(explicit, 0, new ASN1Integer(BigInteger.valueOf(requireExplicitPolicy))));
    }

    if (inhibitPolicyMapping != null) {
      vec.add(new DERTaggedObject(explicit, 1, new ASN1Integer(BigInteger.valueOf(inhibitPolicyMapping))));
    }

    return new DERSequence(vec);
  } //method toXiPolicyConstraints

} // class PolicyConstraints
