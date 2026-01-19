// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.certprofile.xijson.conf.extn.*;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.SubjectKeyIdentifierControl;
import org.xipki.util.extra.type.TripleState;

/**
 * Extension configuration.
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

  private AuthorityInfoAccess authorityInfoAccess;

  private SubjectKeyIdentifierControl subjectKeyIdentifier;

  private BasicConstraints basicConstraints;

  private BiometricInfo biometricInfo;

  private CertificatePolicies certificatePolicies;

  /**
   * For constant encoded Extension.
   */
  private ConstantExtnValue constant;

  private ExtendedKeyUsage extendedKeyUsage;

  private InhibitAnyPolicy inhibitAnyPolicy;

  private KeyUsage keyUsage;

  /**
   * Only for CA, at least one of permittedSubtrees and excludedSubtrees must
   * be present.
   */
  private NameConstraints nameConstraints;

  /**
   * Only for CA.
   */
  private PolicyMappings policyMappings;

  private PolicyConstraints policyConstraints;

  private PrivateKeyUsagePeriod privateKeyUsagePeriod;

  private QcStatements qcStatements;

  private SmimeCapabilities smimeCapabilities;

  private GeneralNameType subjectAltName;

  private SubjectInfoAccess subjectInfoAccess;

  private TlsFeature tlsFeature;

  private CCCSimpleExtensionSchema cccExtensionSchema;

  private CCCInstanceCAExtensionSchema cccInstanceCAExtensionSchema;

  public ExtensionType(ExtensionID type, Boolean critical, Boolean required) {
    this.type = type;
    this.critical  = (critical != null && critical);
    this.required  = (required != null && required);
  }

  public ExtensionID getType() {
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

  public TripleState getInRequest() {
    return inRequest;
  }

  public AuthorityInfoAccess getAuthorityInfoAccess() {
    return authorityInfoAccess;
  }

  public void setAuthorityInfoAccess(AuthorityInfoAccess authorityInfoAccess) {
    this.authorityInfoAccess = authorityInfoAccess;
  }

  public SubjectKeyIdentifierControl getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public void setSubjectKeyIdentifier(
      SubjectKeyIdentifierControl subjectKeyIdentifier) {
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

  public ExtendedKeyUsage getExtendedKeyUsage() {
    return extendedKeyUsage;
  }

  public void setExtendedKeyUsage(ExtendedKeyUsage extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
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

  public PolicyConstraints getPolicyConstraints() {
    return policyConstraints;
  }

  public void setPolicyConstraints(PolicyConstraints policyConstraints) {
    this.policyConstraints = policyConstraints;
  }

  public PrivateKeyUsagePeriod getPrivateKeyUsagePeriod() {
    return privateKeyUsagePeriod;
  }

  public void setPrivateKeyUsagePeriod(
      PrivateKeyUsagePeriod privateKeyUsagePeriod) {
    this.privateKeyUsagePeriod = privateKeyUsagePeriod;
  }

  public QcStatements getQcStatements() {
    return qcStatements;
  }

  public void setQcStatements(QcStatements qcStatements) {
    this.qcStatements = qcStatements;
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

  public CCCSimpleExtensionSchema getCccExtensionSchema() {
    return cccExtensionSchema;
  }

  public void setCccExtensionSchema(
      CCCSimpleExtensionSchema cccExtensionSchema) {
    this.cccExtensionSchema = cccExtensionSchema;
  }

  public CCCInstanceCAExtensionSchema getCccInstanceCAExtensionSchema() {
    return cccInstanceCAExtensionSchema;
  }

  public void setCccInstanceCAExtensionSchema(
      CCCInstanceCAExtensionSchema cccInstanceCAExtensionSchema) {
    this.cccInstanceCAExtensionSchema = cccInstanceCAExtensionSchema;
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();

    ret.put("type", type.getMainAlias());
    // do not encode default value
    ret.put("required", required ? true : null) ;
    // do not encode default value
    ret.put("critical", critical ? true : null) ;
    // do not encode default value
    ret.putEnum("inRequest",
        (inRequest == TripleState.forbidden) ? null : inRequest);

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
      ret.setAuthorityInfoAccess(AuthorityInfoAccess.parse(map));
    }

    map = json.getMap("subjectKeyIdentifier");
    if (map != null) {
      ret.setSubjectKeyIdentifier(SubjectKeyIdentifierControl.parse(map));
    }
    map = json.getMap("basicConstraints");
    if (map != null) {
      ret.setBasicConstraints(BasicConstraints.parse(map));
    }

    map = json.getMap("biometricInfo");
    if (map != null) {
      ret.setBiometricInfo(BiometricInfo.parse(map));
    }

    map = json.getMap("certificatePolicies");
    if (map != null) {
      ret.setCertificatePolicies(CertificatePolicies.parse(map));
    }

    map = json.getMap("constant");
    if (map != null) {
      ret.setConstant(ConstantExtnValue.parse(map));
    }

    map = json.getMap("extendedKeyUsage");
    if (map != null) {
      ret.setExtendedKeyUsage(ExtendedKeyUsage.parse(map));
    }

    map = json.getMap("inhibitAnyPolicy");
    if (map != null) {
      ret.setInhibitAnyPolicy(InhibitAnyPolicy.parse(map));
    }

    map = json.getMap("keyUsage");
    if (map != null) {
      ret.setKeyUsage(KeyUsage.parse(map));
    }

    map = json.getMap("nameConstraints");
    if (map != null) {
      ret.setNameConstraints(NameConstraints.parse(map));
    }

    map = json.getMap("policyMappings");
    if (map != null) {
      ret.setPolicyMappings(PolicyMappings.parse(map));
    }

    map = json.getMap("policyConstraints");
    if (map != null) {
      ret.setPolicyConstraints(PolicyConstraints.parse(map));
    }

    map = json.getMap("privateKeyUsagePeriod");
    if (map != null) {
      ret.setPrivateKeyUsagePeriod(PrivateKeyUsagePeriod.parse(map));
    }

    map = json.getMap("qcStatements");
    if (map != null) {
      ret.setQcStatements(QcStatements.parse(map));
    }

    map = json.getMap("smimeCapabilities");
    if (map != null) {
      ret.setSmimeCapabilities(SmimeCapabilities.parse(map));
    }

    map = json.getMap("subjectAltName");
    if (map != null) {
      ret.setSubjectAltName(GeneralNameType.parse(map));
    }

    map = json.getMap("subjectInfoAccess");
    if (map != null) {
      ret.setSubjectInfoAccess(SubjectInfoAccess.parse(map));
    }

    map = json.getMap("tlsFeature");
    if (map != null) {
      ret.setTlsFeature(TlsFeature.parse(map));
    }

    map = json.getMap("cccExtensionSchema");
    if (map != null) {
      ret.setCccExtensionSchema(CCCSimpleExtensionSchema.parse(map));
    }

    map = json.getMap("cccInstanceCAExtensionSchema");
    if (map != null) {
      ret.setCccInstanceCAExtensionSchema(
          CCCInstanceCAExtensionSchema.parse(map));
    }

    return ret;
  }

}
