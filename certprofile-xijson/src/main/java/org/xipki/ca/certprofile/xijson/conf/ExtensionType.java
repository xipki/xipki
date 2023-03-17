// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.SubjectKeyIdentifierControl;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
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

  private DescribableOid type;

  /**
   * Critical will be considered if both values (true and false) are allowed,
   * otherwise it will be ignored.
   */
  private Boolean critical;

  private Boolean required;

  @Deprecated
  private Boolean permittedInRequest;

  private TripleState inRequest;

  private AdditionalInformation additionalInformation;

  private AdmissionSyntax admissionSyntax;

  private AuthorityInfoAccess authorityInfoAccess;

  private AuthorityKeyIdentifier authorityKeyIdentifier;

  private SubjectKeyIdentifierControl subjectKeyIdentifier;

  private BasicConstraints basicConstraints;

  private BiometricInfo biometricInfo;

  private CertificatePolicies certificatePolicies;

  private CrlDistributionPoints crlDistributionPoints;

  /**
   * For constant encoded Extension.
   */
  private ConstantExtnValue constant;

  private ExtendedKeyUsage extendedKeyUsage;

  private CrlDistributionPoints freshestCrl;

  private InhibitAnyPolicy inhibitAnyPolicy;

  private KeyUsage keyUsage;

  /**
   * Only for CA, at least one of permittedSubtrees and excludedSubtrees must be present.
   */
  private NameConstraints nameConstraints;

  /**
   * Only for CA.
   */
  private PolicyMappings policyMappings;

  private PrivateKeyUsagePeriod privateKeyUsagePeriod;

  private PolicyConstraints policyConstraints;

  private QcStatements qcStatements;

  private Restriction restriction;

  private SmimeCapabilities smimeCapabilities;

  private GeneralNameType subjectAltName;

  private SubjectDirectoryAttributs subjectDirectoryAttributs;

  private SubjectInfoAccess subjectInfoAccess;

  private TlsFeature tlsFeature;

  private ValidityModel validityModel;

  private CCCSimpleExtensionSchema cccExtensionSchema;

  private Object custom;

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
    return critical != null && critical;
  }

  // do not encode the default value.
  public Boolean getRequired() {
    return required != null && required ? Boolean.TRUE :null;
  }

  public void setRequired(Boolean required) {
    this.required = required;
  }

  public boolean required() {
    return required != null && required;
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

  @Deprecated
  public BasicConstraints getBasicConstrains() {
    return getBasicConstraints();
  }

  public BasicConstraints getBasicConstraints() {
    return basicConstraints;
  }

  @Deprecated
  public void setBasicConstrains(BasicConstraints basicConstraints) {
    setBasicConstraints(basicConstraints);
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

  @Override
  public void validate() throws InvalidConfException {
    notNull(type, "type");
    validate(type, additionalInformation, admissionSyntax, authorityInfoAccess, authorityKeyIdentifier);
    validate(basicConstraints, biometricInfo, certificatePolicies, constant, extendedKeyUsage, inhibitAnyPolicy);
    validate(keyUsage, nameConstraints, policyMappings, privateKeyUsagePeriod, policyConstraints, qcStatements);
    validate(restriction, smimeCapabilities, subjectAltName, subjectDirectoryAttributs, subjectInfoAccess);
    validate(subjectKeyIdentifier, tlsFeature, validityModel, cccExtensionSchema);
  } // method validate

}
