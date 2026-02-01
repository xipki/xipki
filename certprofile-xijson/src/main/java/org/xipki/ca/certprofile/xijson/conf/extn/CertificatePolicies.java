// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.ca.certprofile.xijson.CertificatePolicyInformation;
import org.xipki.ca.certprofile.xijson.CertificatePolicyQualifier;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CollectionUtil;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 * Extension CertificatePolicies.
 *
 * @author Lijun Liao (xipki)
 */

public class CertificatePolicies implements JsonEncodable {

  private final List<CertificatePolicyInformationType>
      certificatePolicyInformations;

  public CertificatePolicies(
      List<CertificatePolicyInformationType> certificatePolicyInformations) {
    this.certificatePolicyInformations = Args.notEmpty(
        certificatePolicyInformations, "certificatePolicyInformations");
  }

  public List<CertificatePolicyInformationType>
      certificatePolicyInformations() {
    return certificatePolicyInformations;
  }

  public org.bouncycastle.asn1.x509.CertificatePolicies
      toCertificatePolicies() {
    List<CertificatePolicyInformation> policyInfos = toPolicyInfos();

    int size = policyInfos.size();
    PolicyInformation[] infos = new PolicyInformation[size];

    int idx = 0;
    for (CertificatePolicyInformation policyInfo : policyInfos) {
      List<CertificatePolicyQualifier> qualifiers = policyInfo.qualifiers();
      ASN1Sequence policyQualifiers = CollectionUtil.isEmpty(qualifiers)
          ? null : createX509PolicyQualifiers(qualifiers);
      CertificatePolicyID policyOid = policyInfo.certPolicyId();

      infos[idx++] = (policyQualifiers == null)
          ? new PolicyInformation(policyOid.oid())
          : new PolicyInformation(policyOid.oid(), policyQualifiers);
    }

    return new org.bouncycastle.asn1.x509.CertificatePolicies(infos);
  } // method toX509CertificatePolicies

  private  static ASN1Sequence createX509PolicyQualifiers(
      List<CertificatePolicyQualifier> qualifiers) {
    ASN1EncodableVector qualifierInfos = new ASN1EncodableVector();
    for (CertificatePolicyQualifier qualifier : qualifiers) {
      PolicyQualifierInfo qualifierInfo;
      if (qualifier.cpsUri() != null) {
        qualifierInfo = new PolicyQualifierInfo(qualifier.cpsUri());
      } else if (qualifier.userNotice() != null) {
        UserNotice userNotice = new UserNotice(null, qualifier.userNotice());
        qualifierInfo = new PolicyQualifierInfo(
            PolicyQualifierId.id_qt_unotice, userNotice);
      } else {
        qualifierInfo = null;
      }

      if (qualifierInfo != null) {
        qualifierInfos.add(qualifierInfo);
      }
      //PolicyQualifierId qualifierId
    }

    return new DERSequence(qualifierInfos);
  } // method createPolicyQualifiers

  private List<CertificatePolicyInformation> toPolicyInfos() {
    List<CertificatePolicyInformationType> policyPairs =
        certificatePolicyInformations();
    List<CertificatePolicyInformation> ret =
        new ArrayList<>(policyPairs.size());

    for (CertificatePolicyInformationType policyPair : policyPairs) {
      List<CertificatePolicyQualifier> qualifiers = null;
      if (CollectionUtil.isNotEmpty(policyPair.policyQualifiers)) {
        qualifiers = new ArrayList<>(policyPair.policyQualifiers.size());
        for (PolicyQualifier m : policyPair.policyQualifiers) {
          if (m.type() == PolicyQualifierType.cpsUri) {
            qualifiers.add(
                CertificatePolicyQualifier.getInstanceForCpsUri(m.value));
          } else {
            qualifiers.add(
                CertificatePolicyQualifier.getInstanceForUserNotice(m.value));
          }
        }
      }

      ret.add(new CertificatePolicyInformation(
          policyPair.policyIdentifier(), qualifiers));
    }

    return ret;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEncodables("certificatePolicyInformations",
        this.certificatePolicyInformations);
  }

  public static CertificatePolicies parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("certificatePolicyInformations");
    List<CertificatePolicyInformationType> types = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      types.add(CertificatePolicyInformationType.parse(v));
    }

    return new CertificatePolicies(types);
  }

  public enum PolicyQualifierType {
    cpsUri,
    userNotice
  }

  public static class PolicyQualifier implements JsonEncodable {

    private final PolicyQualifierType type;

    private final String value;

    public PolicyQualifier(PolicyQualifierType type, String value) {
      this.type  = Args.notNull(type, "type");
      this.value = Args.notBlank(value, "value");
    }

    public PolicyQualifierType type() {
      return type;
    }

    public String value() {
      return value;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEnum("type", type).put("value", value);
    }

    public static PolicyQualifier parse(JsonMap json) throws CodecException {
      return new PolicyQualifier(
          PolicyQualifierType.valueOf(json.getNnString("type")),
          json.getNnString("value"));
    }

  } // class PolicyQualifier

  public static class CertificatePolicyInformationType
      implements JsonEncodable {

    private final CertificatePolicyID policyIdentifier;

    private final List<PolicyQualifier> policyQualifiers;

    public CertificatePolicyInformationType(
        CertificatePolicyID policyIdentifier,
        List<PolicyQualifier> policyQualifiers) {
      this.policyIdentifier =
          Args.notNull(policyIdentifier, "policyIdentifier");

      if (policyQualifiers != null) {
        for (PolicyQualifier qualifier : policyQualifiers) {
          if (qualifier.type == PolicyQualifierType.cpsUri) {
            try {
              new URI(qualifier.value);
            } catch (URISyntaxException e) {
              throw new IllegalArgumentException(
                  "invalid URI " + qualifier.value);
            }
          }
        }
      }
      this.policyQualifiers = policyQualifiers;
    }

    public CertificatePolicyID policyIdentifier() {
      return policyIdentifier;
    }

    public List<PolicyQualifier> policyQualifiers() {
      return policyQualifiers == null || policyQualifiers.isEmpty()
          ? null : policyQualifiers;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap().put(
          "policyIdentifier", policyIdentifier.mainAlias());
      if (CollectionUtil.isNotEmpty(policyQualifiers)) {
        ret.putEncodables("policyQualifiers", policyQualifiers);
      }
      return ret;
    }

    public static CertificatePolicyInformationType parse(JsonMap json)
        throws CodecException {
      JsonList list = json.getList("policyQualifiers");
      List<PolicyQualifier> policyQualifiers = null;
      if (list != null) {
        policyQualifiers = new ArrayList<>(list.size());
        for (JsonMap v : list.toMapList()) {
          policyQualifiers.add(PolicyQualifier.parse(v));
        }
      }

      return new CertificatePolicyInformationType(
          CertificatePolicyID.ofOidOrName(
              json.getNnString("policyIdentifier")),
          policyQualifiers);
    }

  }

}
