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
import org.xipki.ca.api.profile.SubjectKeyIdentifierControl;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.security.X509ExtensionType.ConstantExtnValue;
import org.xipki.util.TripleState;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Extension configuration.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionType extends ValidatableConf {

  @JSONField(ordinal = 1)
  private DescribableOid type;

  /**
   * Critical will be considered if both values (true and false) are allowed,
   * otherwise it will be ignored.
   */
  @JSONField(ordinal = 2)
  private Boolean critical;

  @JSONField(ordinal = 3)
  private Boolean required;

  @JSONField(ordinal = 4)
  @Deprecated
  private Boolean permittedInRequest;

  @JSONField(ordinal = 4)
  private TripleState inRequest;

  @JSONField(ordinal = 5)
  private AdditionalInformation additionalInformation;

  @JSONField(ordinal = 5)
  private AdmissionSyntax admissionSyntax;

  @JSONField(ordinal = 5)
  private AuthorityInfoAccess authorityInfoAccess;

  @JSONField(ordinal = 5)
  private AuthorityKeyIdentifier authorityKeyIdentifier;

  @JSONField(ordinal = 5)
  private SubjectKeyIdentifierControl subjectKeyIdentifier;

  @JSONField(ordinal = 5)
  private BasicConstraints basicConstraints;

  @JSONField(ordinal = 5)
  private BiometricInfo biometricInfo;

  @JSONField(ordinal = 5)
  private CertificatePolicies certificatePolicies;

  @JSONField(ordinal = 5)
  private CrlDistributionPoints crlDistributionPoints;

  /**
   * For constant encoded Extension.
   */
  @JSONField(ordinal = 5)
  private ConstantExtnValue constant;

  @JSONField(ordinal = 5)
  private ExtendedKeyUsage extendedKeyUsage;

  @JSONField(ordinal = 5)
  private CrlDistributionPoints freshestCrl;

  @JSONField(ordinal = 5)
  private InhibitAnyPolicy inhibitAnyPolicy;

  @JSONField(ordinal = 5)
  private KeyUsage keyUsage;

  /**
   * Only for CA, at least one of permittedSubtrees and excludedSubtrees must be present.
   */
  @JSONField(ordinal = 5)
  private NameConstraints nameConstraints;

  /**
   * Only for CA.
   */
  @JSONField(ordinal = 5)
  private PolicyMappings policyMappings;

  @JSONField(ordinal = 5)
  private PrivateKeyUsagePeriod privateKeyUsagePeriod;

  @JSONField(ordinal = 5)
  private PolicyConstraints policyConstraints;

  @JSONField(ordinal = 5)
  private QcStatements qcStatements;

  @JSONField(ordinal = 5)
  private Restriction restriction;

  @JSONField(ordinal = 5)
  private SmimeCapabilities smimeCapabilities;

  @JSONField(ordinal = 5)
  private GeneralNameType subjectAltName;

  @JSONField(ordinal = 5)
  private SubjectDirectoryAttributs subjectDirectoryAttributs;

  @JSONField(ordinal = 5)
  private SubjectInfoAccess subjectInfoAccess;

  @JSONField(ordinal = 5)
  private TlsFeature tlsFeature;

  @JSONField(ordinal = 5)
  private ValidityModel validityModel;

  @JSONField(ordinal = 5)
  private CCCSimpleExtensionSchema cccExtensionSchema;

  @JSONField(ordinal = 5)
  private Object custom;

  /**
   * For extension with syntax.
   */
  @JSONField(ordinal = 5)
  private ExtnSyntax syntax;

  public DescribableOid getType() {
    return type;
  }

  public void setType(DescribableOid type) {
    this.type = type;
  }

  // do not encode the default value.
  public Boolean getCritical() {
    return critical != null && critical ? Boolean.TRUE :null;
  }

  public void setCritical(Boolean critical) {
    this.critical = critical;
  }

  public boolean critical() {
    return critical == null ? false : critical;
  }

  // do not encode the default value.
  public Boolean getRequired() {
    return required != null && required ? Boolean.TRUE :null;
  }

  public void setRequired(Boolean required) {
    this.required = required;
  }

  public boolean required() {
    return required == null ? false : required;
  }

  @Deprecated
  public void setPermittedInRequest(boolean permittedInRequest) {
    this.permittedInRequest = permittedInRequest;
  }

  public boolean permittedInRequest() {
    TripleState ts = getInRequest();
    return TripleState.optional == ts || TripleState.required == ts;
  }

  // do not encode the default value.
  public TripleState getInRequest() {
    return inRequest() == TripleState.forbidden ? null : inRequest;
  }

  public TripleState inRequest() {
    if (inRequest != null) {
      return inRequest;
    }

    return (permittedInRequest != null && permittedInRequest) ? TripleState.optional : TripleState.forbidden;
  }

  public void setInRequest(TripleState inRequest) {
    this.inRequest = inRequest;
  }

  public AdditionalInformation getAdditionalInformation() {
    return additionalInformation;
  }

  public void setAdditionalInformation(AdditionalInformation additionalInformation) {
    this.additionalInformation = additionalInformation;
  }

  public AdmissionSyntax getAdmissionSyntax() {
    return admissionSyntax;
  }

  public void setAdmissionSyntax(AdmissionSyntax admissionSyntax) {
    this.admissionSyntax = admissionSyntax;
  }

  public AuthorityInfoAccess getAuthorityInfoAccess() {
    return authorityInfoAccess;
  }

  public void setAuthorityInfoAccess(AuthorityInfoAccess authorityInfoAccess) {
    this.authorityInfoAccess = authorityInfoAccess;
  }

  public AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
    return authorityKeyIdentifier;
  }

  public void setAuthorityKeyIdentifier(AuthorityKeyIdentifier authorityKeyIdentifier) {
    this.authorityKeyIdentifier = authorityKeyIdentifier;
  }

  public SubjectKeyIdentifierControl getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public void setSubjectKeyIdentifier(SubjectKeyIdentifierControl subjectKeyIdentifier) {
    this.subjectKeyIdentifier = subjectKeyIdentifier;
  }

  public BasicConstraints getBasicConstraints() {
    return basicConstraints;
  }

  public void setBasicConstraints(BasicConstraints basicConstraints) {
    this.basicConstraints = basicConstraints;
  }

  public BiometricInfo getBiometricInfo() {
    return biometricInfo;
  }

  public void setBiometricInfo(BiometricInfo biometricInfo) {
    this.biometricInfo = biometricInfo;
  }

  public CertificatePolicies getCertificatePolicies() {
    return certificatePolicies;
  }

  public void setCertificatePolicies(CertificatePolicies certificatePolicies) {
    this.certificatePolicies = certificatePolicies;
  }

  public ConstantExtnValue getConstant() {
    return constant;
  }

  public void setConstant(ConstantExtnValue constant) {
    this.constant = constant;
  }

  public CrlDistributionPoints getCrlDistributionPoints() {
    return crlDistributionPoints;
  }

  public void setCrlDistributionPoints(CrlDistributionPoints crlDistributionPoints) {
    this.crlDistributionPoints = crlDistributionPoints;
  }

  public ExtendedKeyUsage getExtendedKeyUsage() {
    return extendedKeyUsage;
  }

  public void setExtendedKeyUsage(ExtendedKeyUsage extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
  }

  public CrlDistributionPoints getFreshestCrl() {
    return freshestCrl;
  }

  public void setFreshestCrl(CrlDistributionPoints freshestCrl) {
    this.freshestCrl = freshestCrl;
  }

  public InhibitAnyPolicy getInhibitAnyPolicy() {
    return inhibitAnyPolicy;
  }

  public void setInhibitAnyPolicy(InhibitAnyPolicy inhibitAnyPolicy) {
    this.inhibitAnyPolicy = inhibitAnyPolicy;
  }

  public KeyUsage getKeyUsage() {
    return keyUsage;
  }

  public void setKeyUsage(KeyUsage keyUsage) {
    this.keyUsage = keyUsage;
  }

  public NameConstraints getNameConstraints() {
    return nameConstraints;
  }

  public void setNameConstraints(NameConstraints nameConstraints) {
    this.nameConstraints = nameConstraints;
  }

  public PolicyMappings getPolicyMappings() {
    return policyMappings;
  }

  public void setPolicyMappings(PolicyMappings policyMappings) {
    this.policyMappings = policyMappings;
  }

  public PrivateKeyUsagePeriod getPrivateKeyUsagePeriod() {
    return privateKeyUsagePeriod;
  }

  public void setPrivateKeyUsagePeriod(PrivateKeyUsagePeriod privateKeyUsagePeriod) {
    this.privateKeyUsagePeriod = privateKeyUsagePeriod;
  }

  public PolicyConstraints getPolicyConstraints() {
    return policyConstraints;
  }

  public void setPolicyConstraints(PolicyConstraints policyConstraints) {
    this.policyConstraints = policyConstraints;
  }

  public QcStatements getQcStatements() {
    return qcStatements;
  }

  public void setQcStatements(QcStatements qcStatements) {
    this.qcStatements = qcStatements;
  }

  public Restriction getRestriction() {
    return restriction;
  }

  public void setRestriction(Restriction restriction) {
    this.restriction = restriction;
  }

  public SmimeCapabilities getSmimeCapabilities() {
    return smimeCapabilities;
  }

  public void setSmimeCapabilities(SmimeCapabilities smimeCapabilities) {
    this.smimeCapabilities = smimeCapabilities;
  }

  public GeneralNameType getSubjectAltName() {
    return subjectAltName;
  }

  public void setSubjectAltName(GeneralNameType subjectAltName) {
    this.subjectAltName = subjectAltName;
  }

  public SubjectDirectoryAttributs getSubjectDirectoryAttributs() {
    return subjectDirectoryAttributs;
  }

  public void setSubjectDirectoryAttributs(SubjectDirectoryAttributs subjectDirectoryAttributs) {
    this.subjectDirectoryAttributs = subjectDirectoryAttributs;
  }

  public SubjectInfoAccess getSubjectInfoAccess() {
    return subjectInfoAccess;
  }

  public void setSubjectInfoAccess(SubjectInfoAccess subjectInfoAccess) {
    this.subjectInfoAccess = subjectInfoAccess;
  }

  public TlsFeature getTlsFeature() {
    return tlsFeature;
  }

  public void setTlsFeature(TlsFeature tlsFeature) {
    this.tlsFeature = tlsFeature;
  }

  public ValidityModel getValidityModel() {
    return validityModel;
  }

  public void setValidityModel(ValidityModel validityModel) {
    this.validityModel = validityModel;
  }

  public CCCSimpleExtensionSchema getCccExtensionSchema() {
    return cccExtensionSchema;
  }

  public void setCccExtensionSchema(CCCSimpleExtensionSchema cccExtensionSchema) {
    this.cccExtensionSchema = cccExtensionSchema;
  }

  public Object getCustom() {
    return custom;
  }

  public void setCustom(Object custom) {
    this.custom = custom;
  }

  public ExtnSyntax getSyntax() {
    return syntax;
  }

  public void setSyntax(ExtnSyntax syntax) {
    this.syntax = syntax;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(type, "type");
    validate(type, additionalInformation, admissionSyntax, authorityInfoAccess, authorityKeyIdentifier);
    validate(basicConstraints, biometricInfo, certificatePolicies, constant, extendedKeyUsage, inhibitAnyPolicy);
    validate(keyUsage, nameConstraints, policyMappings, privateKeyUsagePeriod, policyConstraints, qcStatements);
    validate(restriction, smimeCapabilities, subjectAltName, subjectDirectoryAttributs, subjectInfoAccess);
    validate(subjectKeyIdentifier, tlsFeature, validityModel, cccExtensionSchema, syntax);
  } // method validate

}
