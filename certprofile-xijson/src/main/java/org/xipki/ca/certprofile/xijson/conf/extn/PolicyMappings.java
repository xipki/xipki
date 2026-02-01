// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.bouncycastle.asn1.x509.CertPolicyId;
import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
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

public class PolicyMappings implements JsonEncodable {

  private final List<PolicyIdMappingType> mappings;

  public PolicyMappings(List<PolicyIdMappingType> mappings) {
    this.mappings = Args.notEmpty(mappings, "mappings");
  }

  public List<PolicyIdMappingType> mappings() {
    return mappings;
  }

  public org.bouncycastle.asn1.x509.PolicyMappings toPolicyMappings() {
    final int n = mappings.size();

    CertPolicyId[] issuerDomainPolicy = new CertPolicyId[n];
    CertPolicyId[] subjectDomainPolicy = new CertPolicyId[n];

    for (int i = 0; i < n; i++) {
      PolicyIdMappingType mapping = mappings.get(i);
      issuerDomainPolicy[i]  = CertPolicyId.getInstance(
          mapping.issuerDomainPolicy().oid());
      subjectDomainPolicy[i] = CertPolicyId.getInstance(
          mapping.subjectDomainPolicy().oid());
    }

    return new org.bouncycastle.asn1.x509.PolicyMappings(
        issuerDomainPolicy, subjectDomainPolicy);
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEncodables("mappings", mappings);
  }

  public static PolicyMappings parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("mappings");
    List<PolicyIdMappingType> mappings = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      mappings.add(PolicyIdMappingType.parse(v));
    }
    return new PolicyMappings(mappings);
  }

  public static class PolicyIdMappingType implements JsonEncodable {

    private final CertificatePolicyID issuerDomainPolicy;

    private final CertificatePolicyID subjectDomainPolicy;

    public PolicyIdMappingType(CertificatePolicyID issuerDomainPolicy,
                               CertificatePolicyID subjectDomainPolicy) {
      this.issuerDomainPolicy =
          Args.notNull(issuerDomainPolicy, "issuerDomainPolicy");
      this.subjectDomainPolicy =
          Args.notNull(subjectDomainPolicy, "subjectDomainPolicy");
    }

    public CertificatePolicyID issuerDomainPolicy() {
      return issuerDomainPolicy;
    }

    public CertificatePolicyID subjectDomainPolicy() {
      return subjectDomainPolicy;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      if (issuerDomainPolicy != null) {
        ret.put("issuerDomainPolicy", issuerDomainPolicy.mainAlias());
      }
      if (issuerDomainPolicy != null) {
        ret.put("subjectDomainPolicy", subjectDomainPolicy.mainAlias());
      }
      return ret;
    }

    public static PolicyIdMappingType parse(JsonMap json)
        throws CodecException {
      String str = json.getString("issuerDomainPolicy");
      CertificatePolicyID issuerDomainPolicy = (str == null) ? null
          : CertificatePolicyID.ofOidOrName(str);

      str = json.getString("subjectDomainPolicy");
      CertificatePolicyID subjectDomainPolicy = (str == null) ? null
          : CertificatePolicyID.ofOidOrName(str);

      return new PolicyIdMappingType(issuerDomainPolicy, subjectDomainPolicy);
    }

  } // class PolicyIdMappingType

}
