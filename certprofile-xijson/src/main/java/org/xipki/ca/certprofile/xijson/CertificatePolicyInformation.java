// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.List;

/**
 * Control of the CertificatePolicyInformation (in the extension
 * CertificatePolicies).
 *
 * @author Lijun Liao (xipki)
 */

public class CertificatePolicyInformation {

  private final CertificatePolicyID certPolicyId;

  private final List<CertificatePolicyQualifier> qualifiers;

  public CertificatePolicyInformation(
      CertificatePolicyID certPolicyId,
      List<CertificatePolicyQualifier> qualifiers) {
    this.certPolicyId = Args.notNull(certPolicyId, "certPolicyId");
    this.qualifiers = CollectionUtil.unmodifiableList(qualifiers);
  }

  public CertificatePolicyID certPolicyId() {
    return certPolicyId;
  }

  public List<CertificatePolicyQualifier> qualifiers() {
    return qualifiers;
  }

}
