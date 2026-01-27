// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.ca.certprofile.xijson.conf.extn.CertificatePolicies;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension CertificatePolicies.
 *
 * @author Lijun Liao (xipki)
 */

public class V1CertificatePolicies {

  private static class CertificatePolicyInformationType {

    private final DescribableOid policyIdentifier;

    private final List<CertificatePolicies.PolicyQualifier> policyQualifiers;

    private CertificatePolicyInformationType(
        DescribableOid policyIdentifier,
        List<CertificatePolicies.PolicyQualifier> policyQualifiers) {
      this.policyIdentifier =
          Args.notNull(policyIdentifier, "policyIdentifier");
      this.policyQualifiers = policyQualifiers;
    }

    public static CertificatePolicyInformationType parse(JsonMap json)
        throws CodecException {
      JsonList list = json.getList("policyQualifiers");
      List<CertificatePolicies.PolicyQualifier> policyQualifiers = null;
      if (list != null) {
        policyQualifiers = new ArrayList<>(list.size());
        for (JsonMap v : list.toMapList()) {
          policyQualifiers.add(CertificatePolicies.PolicyQualifier.parse(v));
        }
      }
      return new CertificatePolicyInformationType(
          DescribableOid.parseNn(json, "policyIdentifier"),
          policyQualifiers);
    }

  }

  private final List<CertificatePolicyInformationType>
      certificatePolicyInformations;

  private V1CertificatePolicies(
      List<CertificatePolicyInformationType> certificatePolicyInformations) {
    this.certificatePolicyInformations = Args.notEmpty(
        certificatePolicyInformations, "certificatePolicyInformations");
  }

  public static V1CertificatePolicies parse(JsonMap json)
      throws CodecException {
    JsonList list = json.getNnList("certificatePolicyInformations");
    List<CertificatePolicyInformationType> types = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      types.add(CertificatePolicyInformationType.parse(v));
    }
    return new V1CertificatePolicies(types);
  }

  public CertificatePolicies toV2() {
    List<CertificatePolicies.CertificatePolicyInformationType> list =
        new ArrayList<>(certificatePolicyInformations.size());

    for (CertificatePolicyInformationType info
        : certificatePolicyInformations) {
      list.add(new CertificatePolicies.CertificatePolicyInformationType(
              CertificatePolicyID.ofOid(info.policyIdentifier.oid()),
              info.policyQualifiers));
    }

    return new CertificatePolicies(list);
  }

}
