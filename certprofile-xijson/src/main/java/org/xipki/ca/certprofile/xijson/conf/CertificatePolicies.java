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

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.certprofile.xijson.CertificatePolicyInformation;
import org.xipki.ca.certprofile.xijson.CertificatePolicyQualifier;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

import com.alibaba.fastjson.annotation.JSONField;

/**
 * Extension CertificatePolicies.
 *
 * @author Lijun Liao
 */

public class CertificatePolicies extends ValidatableConf {

  public static enum PolicyQualfierType {
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
    public void validate()
        throws InvalidConfException {
      notNull(type, "type");
      notBlank(value, "value");
    }

  } // class PolicyQualifier

  public static class CertificatePolicyInformationType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableOid policyIdentifier;

    @JSONField(ordinal = 2)
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
    public void validate()
        throws InvalidConfException {
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

  public void setCertificatePolicyInformations(
      List<CertificatePolicyInformationType> certificatePolicyInformations) {
    this.certificatePolicyInformations = certificatePolicyInformations;
  }

  @Override
  public void validate()
      throws InvalidConfException {
    notEmpty(certificatePolicyInformations, "certificatePolicyInformations");
    validate(certificatePolicyInformations);
  }

  public org.bouncycastle.asn1.x509.CertificatePolicies toXiCertificatePolicies()
      throws CertprofileException {
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

      CertificatePolicyInformation cpi = new CertificatePolicyInformation(
          policyPair.getPolicyIdentifier().getOid(), qualifiers);
      policyInfos.add(cpi);
    }

    int size = policyInfos.size();
    PolicyInformation[] infos = new PolicyInformation[size];

    int idx = 0;
    for (CertificatePolicyInformation policyInfo : policyInfos) {
      String policyId = policyInfo.getCertPolicyId();
      List<CertificatePolicyQualifier> qualifiers = policyInfo.getQualifiers();

      ASN1Sequence policyQualifiers = null;
      if (CollectionUtil.isNotEmpty(qualifiers)) {
        policyQualifiers = createPolicyQualifiers(qualifiers);
      }

      ASN1ObjectIdentifier policyOid = new ASN1ObjectIdentifier(policyId);
      infos[idx++] = (policyQualifiers == null) ? new PolicyInformation(policyOid)
          : new PolicyInformation(policyOid, policyQualifiers);
    }

    return new org.bouncycastle.asn1.x509.CertificatePolicies(infos);
  } // method toXiCertificatePolicies

  private  static ASN1Sequence createPolicyQualifiers(
      List<CertificatePolicyQualifier> qualifiers) {
    Args.notNull(qualifiers, "qualifiers");
    List<PolicyQualifierInfo> qualifierInfos = new ArrayList<>(qualifiers.size());
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

    return new DERSequence(qualifierInfos.toArray(new PolicyQualifierInfo[0]));
  } // method createPolicyQualifiers

} // class CertificatePolicies
