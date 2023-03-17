// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.xipki.ca.certprofile.xijson.CertificatePolicyInformation;
import org.xipki.ca.certprofile.xijson.CertificatePolicyQualifier;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Extension CertificatePolicies.
 *
 * @author Lijun Liao (xipki)
 */

public class CertificatePolicies extends ValidatableConf {

  public enum PolicyQualfierType {
    cpsUri,
    userNotice
  } // class PolicyQualfierType

  public static class PolicyQualifier extends ValidatableConf {

    private PolicyQualfierType type;

    private String value;

    public PolicyQualfierType getType() {
      return type;
    }

    public void setType(PolicyQualfierType type) {
      this.type = type;
    }

    public String getValue() {
      return value;
    }

    public void setValue(String value) {
      this.value = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(type, "type");
      notBlank(value, "value");
    }

  } // class PolicyQualifier

  public static class CertificatePolicyInformationType extends ValidatableConf {

    private DescribableOid policyIdentifier;

    private List<PolicyQualifier> policyQualifiers;

    public DescribableOid getPolicyIdentifier() {
      return policyIdentifier;
    }

    public void setPolicyIdentifier(DescribableOid policyIdentifier) {
      this.policyIdentifier = policyIdentifier;
    }

    public List<PolicyQualifier> getPolicyQualifiers() {
      if (policyQualifiers == null) {
        policyQualifiers = new LinkedList<>();
      }
      return policyQualifiers;
    }

    public void setPolicyQualifiers(List<PolicyQualifier> policyQualifiers) {
      this.policyQualifiers = policyQualifiers;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(policyIdentifier, "policyIdentifier");
      validate(policyIdentifier);
      validate(policyQualifiers);
    }

  }

  private List<CertificatePolicyInformationType> certificatePolicyInformations;

  public List<CertificatePolicyInformationType> getCertificatePolicyInformations() {
    if (certificatePolicyInformations == null) {
      this.certificatePolicyInformations = new LinkedList<>();
    }
    return certificatePolicyInformations;
  }

  public void setCertificatePolicyInformations(List<CertificatePolicyInformationType> certificatePolicyInformations) {
    this.certificatePolicyInformations = certificatePolicyInformations;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(certificatePolicyInformations, "certificatePolicyInformations");
    validate(certificatePolicyInformations);
  }

  public org.bouncycastle.asn1.x509.CertificatePolicies toXiCertificatePolicies() {
    List<CertificatePolicyInformationType> policyPairs = getCertificatePolicyInformations();
    List<CertificatePolicyInformation> policyInfos = new ArrayList<>(policyPairs.size());

    for (CertificatePolicyInformationType policyPair : policyPairs) {
      List<CertificatePolicyQualifier> qualifiers = null;

      List<PolicyQualifier> policyQualifiers = policyPair.getPolicyQualifiers();
      if (!policyQualifiers.isEmpty()) {
        qualifiers = new ArrayList<>(policyQualifiers.size());
        for (PolicyQualifier m : policyQualifiers) {
          CertificatePolicyQualifier qualifier = m.getType() == PolicyQualfierType.cpsUri
              ? CertificatePolicyQualifier.getInstanceForCpsUri(m.getValue())
              : CertificatePolicyQualifier.getInstanceForUserNotice(m.getValue());
          qualifiers.add(qualifier);
        }
      }

      policyInfos.add(new CertificatePolicyInformation(policyPair.getPolicyIdentifier().getOid(), qualifiers));
    }

    int size = policyInfos.size();
    PolicyInformation[] infos = new PolicyInformation[size];

    int idx = 0;
    for (CertificatePolicyInformation policyInfo : policyInfos) {
      List<CertificatePolicyQualifier> qualifiers = policyInfo.getQualifiers();
      ASN1Sequence policyQualifiers = CollectionUtil.isEmpty(qualifiers) ? null : createPolicyQualifiers(qualifiers);
      ASN1ObjectIdentifier policyOid = new ASN1ObjectIdentifier(policyInfo.getCertPolicyId());

      infos[idx++] = (policyQualifiers == null)
          ? new PolicyInformation(policyOid) : new PolicyInformation(policyOid, policyQualifiers);
    }

    return new org.bouncycastle.asn1.x509.CertificatePolicies(infos);
  } // method toXiCertificatePolicies

  private  static ASN1Sequence createPolicyQualifiers(List<CertificatePolicyQualifier> qualifiers) {
    Args.notNull(qualifiers, "qualifiers");
    ASN1EncodableVector qualifierInfos = new ASN1EncodableVector();
    for (CertificatePolicyQualifier qualifier : qualifiers) {
      PolicyQualifierInfo qualifierInfo;
      if (qualifier.getCpsUri() != null) {
        qualifierInfo = new PolicyQualifierInfo(qualifier.getCpsUri());
      } else if (qualifier.getUserNotice() != null) {
        UserNotice userNotice = new UserNotice(null, qualifier.getUserNotice());
        qualifierInfo = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, userNotice);
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

} // class CertificatePolicies
