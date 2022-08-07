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
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Extension PolicyMappings.
 * Only for CA.
 *
 * @author Lijun Liao
 */

public class PolicyMappings extends ValidatableConf {

  public static class PolicyIdMappingType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableOid issuerDomainPolicy;

    @JSONField(ordinal = 2)
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
    public void validate()
        throws InvalidConfException {
      notNull(issuerDomainPolicy, "issuerDomainPolicy");
      validate(issuerDomainPolicy);
      notNull(subjectDomainPolicy, "subjectDomainPolicy");
      validate(subjectDomainPolicy);
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
  public void validate()
      throws InvalidConfException {
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
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(
          mapping.getIssuerDomainPolicy().getOid());
      issuerDomainPolicy[i] = CertPolicyId.getInstance(oid);

      oid = new ASN1ObjectIdentifier(mapping.getSubjectDomainPolicy().getOid());
      subjectDomainPolicy[i] = CertPolicyId.getInstance(oid);
    }

    return new org.bouncycastle.asn1.x509.PolicyMappings(issuerDomainPolicy, subjectDomainPolicy);
  } // method toXiPolicyMappings

} // class PolicyMappings
