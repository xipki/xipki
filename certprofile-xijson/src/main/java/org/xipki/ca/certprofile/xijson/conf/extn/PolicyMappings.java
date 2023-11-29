// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Extension PolicyMappings.
 * Only for CA.
 *
 * @author Lijun Liao (xipki)
 */

public class PolicyMappings extends ValidableConf {

  public static class PolicyIdMappingType extends ValidableConf {

    private DescribableOid issuerDomainPolicy;

    private DescribableOid subjectDomainPolicy;

    public DescribableOid getIssuerDomainPolicy() {
      return issuerDomainPolicy;
    }

    public void setIssuerDomainPolicy(DescribableOid issuerDomainPolicy) {
      this.issuerDomainPolicy = issuerDomainPolicy;
    }

    public DescribableOid getSubjectDomainPolicy() {
      return subjectDomainPolicy;
    }

    public void setSubjectDomainPolicy(DescribableOid subjectDomainPolicy) {
      this.subjectDomainPolicy = subjectDomainPolicy;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(issuerDomainPolicy, "issuerDomainPolicy");
      notNull(subjectDomainPolicy, "subjectDomainPolicy");
      validate(issuerDomainPolicy, subjectDomainPolicy);
    }

  } // class PolicyIdMappingType

  private List<PolicyIdMappingType> mappings;

  public List<PolicyIdMappingType> getMappings() {
    if (mappings == null) {
      mappings = new LinkedList<>();
    }
    return mappings;
  }

  public void setMappings(List<PolicyIdMappingType> mappings) {
    this.mappings = mappings;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(mappings, "mappings");
    validate(mappings);
  }

  public org.bouncycastle.asn1.x509.PolicyMappings toXiPolicyMappings() {
    List<PolicyIdMappingType> mappings = getMappings();
    final int n = mappings.size();

    CertPolicyId[] issuerDomainPolicy = new CertPolicyId[n];
    CertPolicyId[] subjectDomainPolicy = new CertPolicyId[n];

    for (int i = 0; i < n; i++) {
      PolicyIdMappingType mapping = mappings.get(i);

      issuerDomainPolicy[i] = CertPolicyId.getInstance(
          new ASN1ObjectIdentifier(mapping.getIssuerDomainPolicy().getOid()));

      subjectDomainPolicy[i] = CertPolicyId.getInstance(
          new ASN1ObjectIdentifier(mapping.getSubjectDomainPolicy().getOid()));
    }

    return new org.bouncycastle.asn1.x509.PolicyMappings(issuerDomainPolicy, subjectDomainPolicy);
  } // method toXiPolicyMappings

} // class PolicyMappings
