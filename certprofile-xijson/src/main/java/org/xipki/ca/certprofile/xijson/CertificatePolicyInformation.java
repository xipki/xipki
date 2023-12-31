// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;

import java.util.List;

/**
 * Control of the CertificatePolicyInformation (in the extension CertificatePolicies).
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertificatePolicyInformation {

  private final String certPolicyId;

  private final List<CertificatePolicyQualifier> qualifiers;

  public CertificatePolicyInformation(String certPolicyId, List<CertificatePolicyQualifier> qualifiers) {
    this.certPolicyId = Args.notBlank(certPolicyId, "certPolicyId");
    this.qualifiers = CollectionUtil.unmodifiableList(qualifiers);
  }

  public String getCertPolicyId() {
    return certPolicyId;
  }

  public List<CertificatePolicyQualifier> getQualifiers() {
    return qualifiers;
  }

}
