// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyMappings;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension PolicyMappings.
 * Only for CA.
 *
 * @author Lijun Liao (xipki)
 */

public class V1PolicyMappings {

  private static class PolicyIdMappingType {

    private final DescribableOid issuerDomainPolicy;

    private final DescribableOid subjectDomainPolicy;

    public PolicyIdMappingType(DescribableOid issuerDomainPolicy,
                               DescribableOid subjectDomainPolicy) {
      this.issuerDomainPolicy = Args.notNull(
          issuerDomainPolicy,  "issuerDomainPolicy");
      this.subjectDomainPolicy = Args.notNull(
          subjectDomainPolicy, "subjectDomainPolicy");
    }

    public static PolicyIdMappingType parse(JsonMap json)
        throws CodecException {
      return new PolicyIdMappingType(
          DescribableOid.parseNn(json, "issuerDomainPolicy"),
          DescribableOid.parseNn(json, "subjectDomainPolicy"));
    }

  } // class PolicyIdMappingType

  private final List<PolicyIdMappingType> mappings;

  private V1PolicyMappings(List<PolicyIdMappingType> mappings) {
    this.mappings = Args.notEmpty(mappings, "mappings");
  }

  public PolicyMappings toV2() {
    List<PolicyMappings.PolicyIdMappingType> list =
        new ArrayList<>(mappings.size());
    for (PolicyIdMappingType t : mappings) {
      CertificatePolicyID issuerDomainPolicy = null;
      if (t.issuerDomainPolicy != null) {
        issuerDomainPolicy =
            CertificatePolicyID.ofOid(t.issuerDomainPolicy.oid());
      }

      CertificatePolicyID subjectDomainPolicy = null;
      if (t.subjectDomainPolicy != null) {
        subjectDomainPolicy =
            CertificatePolicyID.ofOid(t.subjectDomainPolicy.oid());
      }

      list.add(new PolicyMappings.PolicyIdMappingType(
          issuerDomainPolicy, subjectDomainPolicy));
    }

    return new PolicyMappings(list);
  }

  public static V1PolicyMappings parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("mappings");
    List<PolicyIdMappingType> mappings = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      mappings.add(PolicyIdMappingType.parse(v));
    }
    return new V1PolicyMappings(mappings);
  }

}
