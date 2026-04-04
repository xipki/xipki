// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.TripleState;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.type.SubjectKeyIdentifierControl;

/**
 * Extension Type type definition.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class ExtensionType implements JsonEncodable {

  private final ExtensionID type;

  /**
   * Critical will be considered if both values (true and false) are allowed,
   * otherwise it will be ignored.
   */
  private final boolean critical;

  private final boolean required;

  private TripleState inRequest = TripleState.forbidden;

  private ExtensionValueConf.AuthorityInfoAccess authorityInfoAccess;

  private SubjectKeyIdentifierControl subjectKeyIdentifier;

  private ExtensionValueConf.BasicConstraints basicConstraints;

  private ExtensionValueConf.BiometricInfo biometricInfo;

  private ExtensionValueConf.CertificatePolicies certificatePolicies;

  /**
   * For constant encoded Extension.
   */
  private ConstantExtnValue constant;

  private ExtensionValueConf.ExtendedKeyUsage extendedKeyUsage;

  private ExtensionValueConf.InhibitAnyPolicy inhibitAnyPolicy;

  private ExtensionValueConf.KeyUsage keyUsage;

  /**
   * Only for CA, at least one of permittedSubtrees and excludedSubtrees must
   * be present.
   */
  private ExtensionValueConf.NameConstraints nameConstraints;

  /**
   * Only for CA.
   */
  private ExtensionValueConf.PolicyMappings policyMappings;

  private ExtensionValueConf.PolicyConstraints policyConstraints;

  private ExtensionValueConf.PrivateKeyUsagePeriod privateKeyUsagePeriod;

  private ExtensionValueConf.QcStatements qcStatements;

  private ExtensionValueConf.SmimeCapabilities smimeCapabilities;

  private GeneralNameType subjectAltName;

  private ExtensionValueConf.SubjectInfoAccess subjectInfoAccess;

  private ExtensionValueConf.TlsFeature tlsFeature;

  private ExtensionValueConf.CCCSimpleExtensionSchema cccExtensionSchema;

  private ExtensionValueConf.CCCInstanceCAExtensionSchema cccInstanceCAExtensionSchema;

  private ExtensionValueConf.MicrosoftCertificateTemplateName microsoftCertificateTemplateName;

  private ExtensionValueConf.MicrosoftCertificateTemplateInformation
      microsoftCertificateTemplateInformation;

  private ExtensionValueConf.MicrosoftSID microsoftSID;

  public ExtensionType(ExtensionID type, Boolean critical, Boolean required) {
    this.type = type;
    this.critical  = (critical != null && critical);
    this.required  = (required != null && required);
  }

  public ExtensionID type() {
    return type;
  }

  public boolean isCritical() {
    return critical;
  }

  public boolean isRequired() {
    return required;
  }

  public void setInRequest(TripleState inRequest) {
    this.inRequest = (inRequest == null) ? TripleState.forbidden : inRequest;
  }

  public TripleState inRequest() {
    return inRequest;
  }

  public ExtensionValueConf.AuthorityInfoAccess authorityInfoAccess() {
    return authorityInfoAccess;
  }

  public void setAuthorityInfoAccess(ExtensionValueConf.AuthorityInfoAccess authorityInfoAccess) {
    this.authorityInfoAccess = authorityInfoAccess;
  }

  public SubjectKeyIdentifierControl subjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public void setSubjectKeyIdentifier(SubjectKeyIdentifierControl subjectKeyIdentifier) {
    this.subjectKeyIdentifier = subjectKeyIdentifier;
  }

  public ExtensionValueConf.BasicConstraints basicConstraints() {
    return basicConstraints;
  }

  public void setBasicConstraints(ExtensionValueConf.BasicConstraints basicConstraints) {
    this.basicConstraints = basicConstraints;
  }

  public ExtensionValueConf.BiometricInfo biometricInfo() {
    return biometricInfo;
  }

  public void setBiometricInfo(ExtensionValueConf.BiometricInfo biometricInfo) {
    this.biometricInfo = biometricInfo;
  }

  public ExtensionValueConf.CertificatePolicies certificatePolicies() {
    return certificatePolicies;
  }

  public void setCertificatePolicies(ExtensionValueConf.CertificatePolicies certificatePolicies) {
    this.certificatePolicies = certificatePolicies;
  }

  public ConstantExtnValue constant() {
    return constant;
  }

  public void setConstant(ConstantExtnValue constant) {
    this.constant = constant;
  }

  public ExtensionValueConf.ExtendedKeyUsage extendedKeyUsage() {
    return extendedKeyUsage;
  }

  public void setExtendedKeyUsage(ExtensionValueConf.ExtendedKeyUsage extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
  }

  public ExtensionValueConf.InhibitAnyPolicy inhibitAnyPolicy() {
    return inhibitAnyPolicy;
  }

  public void setInhibitAnyPolicy(ExtensionValueConf.InhibitAnyPolicy inhibitAnyPolicy) {
    this.inhibitAnyPolicy = inhibitAnyPolicy;
  }

  public ExtensionValueConf.KeyUsage keyUsage() {
    return keyUsage;
  }

  public void setKeyUsage(ExtensionValueConf.KeyUsage keyUsage) {
    this.keyUsage = keyUsage;
  }

  public ExtensionValueConf.NameConstraints nameConstraints() {
    return nameConstraints;
  }

  public void setNameConstraints(ExtensionValueConf.NameConstraints nameConstraints) {
    this.nameConstraints = nameConstraints;
  }

  public ExtensionValueConf.PolicyMappings policyMappings() {
    return policyMappings;
  }

  public void setPolicyMappings(ExtensionValueConf.PolicyMappings policyMappings) {
    this.policyMappings = policyMappings;
  }

  public ExtensionValueConf.PolicyConstraints policyConstraints() {
    return policyConstraints;
  }

  public void setPolicyConstraints(ExtensionValueConf.PolicyConstraints policyConstraints) {
    this.policyConstraints = policyConstraints;
  }

  public ExtensionValueConf.PrivateKeyUsagePeriod privateKeyUsagePeriod() {
    return privateKeyUsagePeriod;
  }

  public void setPrivateKeyUsagePeriod(
      ExtensionValueConf.PrivateKeyUsagePeriod privateKeyUsagePeriod) {
    this.privateKeyUsagePeriod = privateKeyUsagePeriod;
  }

  public ExtensionValueConf.QcStatements qcStatements() {
    return qcStatements;
  }

  public void setQcStatements(ExtensionValueConf.QcStatements qcStatements) {
    this.qcStatements = qcStatements;
  }

  public ExtensionValueConf.SmimeCapabilities smimeCapabilities() {
    return smimeCapabilities;
  }

  public void setSmimeCapabilities(ExtensionValueConf.SmimeCapabilities smimeCapabilities) {
    this.smimeCapabilities = smimeCapabilities;
  }

  public GeneralNameType subjectAltName() {
    return subjectAltName;
  }

  public void setSubjectAltName(GeneralNameType subjectAltName) {
    this.subjectAltName = subjectAltName;
  }

  public ExtensionValueConf.SubjectInfoAccess subjectInfoAccess() {
    return subjectInfoAccess;
  }

  public void setSubjectInfoAccess(ExtensionValueConf.SubjectInfoAccess subjectInfoAccess) {
    this.subjectInfoAccess = subjectInfoAccess;
  }

  public ExtensionValueConf.TlsFeature tlsFeature() {
    return tlsFeature;
  }

  public void setTlsFeature(ExtensionValueConf.TlsFeature tlsFeature) {
    this.tlsFeature = tlsFeature;
  }

  public ExtensionValueConf.CCCSimpleExtensionSchema cccExtensionSchema() {
    return cccExtensionSchema;
  }

  public void setCccExtensionSchema(
      ExtensionValueConf.CCCSimpleExtensionSchema cccExtensionSchema) {
    this.cccExtensionSchema = cccExtensionSchema;
  }

  public ExtensionValueConf.CCCInstanceCAExtensionSchema cccInstanceCAExtensionSchema() {
    return cccInstanceCAExtensionSchema;
  }

  public void setCccInstanceCAExtensionSchema(
      ExtensionValueConf.CCCInstanceCAExtensionSchema cccInstanceCAExtensionSchema) {
    this.cccInstanceCAExtensionSchema = cccInstanceCAExtensionSchema;
  }

  public ExtensionValueConf.MicrosoftCertificateTemplateName microsoftCertificateTemplateName() {
    return microsoftCertificateTemplateName;
  }

  public void setMicrosoftCertificateTemplateName(
      ExtensionValueConf.MicrosoftCertificateTemplateName microsoftCertificateTemplateName) {
    this.microsoftCertificateTemplateName = microsoftCertificateTemplateName;
  }

  public ExtensionValueConf.MicrosoftCertificateTemplateInformation
      microsoftCertificateTemplateInformation() {
    return microsoftCertificateTemplateInformation;
  }

  public void setMicrosoftCertificateTemplateInformation(
      ExtensionValueConf.MicrosoftCertificateTemplateInformation
          microsoftCertificateTemplateInformation) {
    this.microsoftCertificateTemplateInformation = microsoftCertificateTemplateInformation;
  }

  public ExtensionValueConf.MicrosoftSID microsoftSID() {
    return microsoftSID;
  }

  public void setMicrosoftSID(ExtensionValueConf.MicrosoftSID microsoftSID) {
    this.microsoftSID = microsoftSID;
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();

    ret.put("type", type.mainAlias());
    // do not encode default value
    ret.put("required", required ? true : null) ;
    // do not encode default value
    ret.put("critical", critical ? true : null) ;
    // do not encode default value
    ret.putEnum("inRequest", (inRequest == TripleState.forbidden) ? null : inRequest);

    ret.put("authorityInfoAccess", authorityInfoAccess);
    ret.put("subjectKeyIdentifier", subjectKeyIdentifier);
    ret.put("basicConstraints", basicConstraints);
    ret.put("biometricInfo", biometricInfo);
    ret.put("certificatePolicies", certificatePolicies);
    ret.put("constant", constant);
    ret.put("extendedKeyUsage", extendedKeyUsage);
    ret.put("inhibitAnyPolicy", inhibitAnyPolicy);
    ret.put("keyUsage", keyUsage);
    ret.put("nameConstraints", nameConstraints);
    ret.put("policyMappings", policyMappings);
    ret.put("policyConstraints", policyConstraints);
    ret.put("privateKeyUsagePeriod", privateKeyUsagePeriod);
    ret.put("qcStatements", qcStatements);
    ret.put("smimeCapabilities", smimeCapabilities);
    ret.put("subjectAltName", subjectAltName);
    ret.put("subjectInfoAccess", subjectInfoAccess);
    ret.put("tlsFeature", tlsFeature);
    ret.put("cccExtensionSchema", cccExtensionSchema);
    ret.put("cccInstanceCAExtensionSchema", cccInstanceCAExtensionSchema);
    ret.put("microsoftCertificateTemplateName", microsoftCertificateTemplateName);
    ret.put("microsoftCertificateTemplateInformation", microsoftCertificateTemplateInformation);
    ret.put("microsoftSID", microsoftSID);
    return ret;
  }

  public static ExtensionType parse(JsonMap json) throws CodecException {
    ExtensionID type = ExtensionID.ofOidOrName(json.getNnString("type"));
    ExtensionType ret = new ExtensionType(type, json.getBool("critical"),
        json.getBool("required"));

    TripleState inRequest = json.getEnum("inRequest", TripleState.class);
    if (inRequest != null) {
      ret.setInRequest(inRequest);
    }

    JsonMap map = json.getMap("authorityInfoAccess");
    if (map != null) {
      ret.setAuthorityInfoAccess(ExtensionValueConf.AuthorityInfoAccess.parse(map));
    }

    map = json.getMap("subjectKeyIdentifier");
    if (map != null) {
      ret.setSubjectKeyIdentifier(SubjectKeyIdentifierControl.parse(map));
    }
    map = json.getMap("basicConstraints");
    if (map != null) {
      ret.setBasicConstraints(ExtensionValueConf.BasicConstraints.parse(map));
    }

    map = json.getMap("biometricInfo");
    if (map != null) {
      ret.setBiometricInfo(ExtensionValueConf.BiometricInfo.parse(map));
    }

    map = json.getMap("certificatePolicies");
    if (map != null) {
      ret.setCertificatePolicies(ExtensionValueConf.CertificatePolicies.parse(map));
    }

    map = json.getMap("constant");
    if (map != null) {
      ret.setConstant(ConstantExtnValue.parse(map));
    }

    map = json.getMap("extendedKeyUsage");
    if (map != null) {
      ret.setExtendedKeyUsage(ExtensionValueConf.ExtendedKeyUsage.parse(map));
    }

    map = json.getMap("inhibitAnyPolicy");
    if (map != null) {
      ret.setInhibitAnyPolicy(ExtensionValueConf.InhibitAnyPolicy.parse(map));
    }

    map = json.getMap("keyUsage");
    if (map != null) {
      ret.setKeyUsage(ExtensionValueConf.KeyUsage.parse(map));
    }

    map = json.getMap("nameConstraints");
    if (map != null) {
      ret.setNameConstraints(ExtensionValueConf.NameConstraints.parse(map));
    }

    map = json.getMap("policyMappings");
    if (map != null) {
      ret.setPolicyMappings(ExtensionValueConf.PolicyMappings.parse(map));
    }

    map = json.getMap("policyConstraints");
    if (map != null) {
      ret.setPolicyConstraints(ExtensionValueConf.PolicyConstraints.parse(map));
    }

    map = json.getMap("privateKeyUsagePeriod");
    if (map != null) {
      ret.setPrivateKeyUsagePeriod(ExtensionValueConf.PrivateKeyUsagePeriod.parse(map));
    }

    map = json.getMap("qcStatements");
    if (map != null) {
      ret.setQcStatements(ExtensionValueConf.QcStatements.parse(map));
    }

    map = json.getMap("smimeCapabilities");
    if (map != null) {
      ret.setSmimeCapabilities(ExtensionValueConf.SmimeCapabilities.parse(map));
    }

    map = json.getMap("subjectAltName");
    if (map != null) {
      ret.setSubjectAltName(GeneralNameType.parse(map));
    }

    map = json.getMap("subjectInfoAccess");
    if (map != null) {
      ret.setSubjectInfoAccess(ExtensionValueConf.SubjectInfoAccess.parse(map));
    }

    map = json.getMap("tlsFeature");
    if (map != null) {
      ret.setTlsFeature(ExtensionValueConf.TlsFeature.parse(map));
    }

    map = json.getMap("cccExtensionSchema");
    if (map != null) {
      ret.setCccExtensionSchema(ExtensionValueConf.CCCSimpleExtensionSchema.parse(map));
    }

    map = json.getMap("cccInstanceCAExtensionSchema");
    if (map != null) {
      ret.setCccInstanceCAExtensionSchema(
          ExtensionValueConf.CCCInstanceCAExtensionSchema.parse(map));
    }

    map = json.getMap("microsoftCertificateTemplateName");
    if (map != null) {
      ret.setMicrosoftCertificateTemplateName(
          ExtensionValueConf.MicrosoftCertificateTemplateName.decode(map));
    }

    map = json.getMap("microsoftCertificateTemplateInformation");
    if (map != null) {
      ret.setMicrosoftCertificateTemplateInformation(
          ExtensionValueConf.MicrosoftCertificateTemplateInformation.decode(map));
    }

    map = json.getMap("microsoftSID");
    if (map != null) {
      ret.setMicrosoftSID(ExtensionValueConf.MicrosoftSID.decode(map));
    }

    return ret;
  }

}
