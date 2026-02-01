// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf;

import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.extn.AuthorityInfoAccess;
import org.xipki.ca.certprofile.xijson.conf.extn.BasicConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.CCCInstanceCAExtensionSchema;
import org.xipki.ca.certprofile.xijson.conf.extn.CCCSimpleExtensionSchema;
import org.xipki.ca.certprofile.xijson.conf.extn.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PrivateKeyUsagePeriod;
import org.xipki.ca.certprofile.xijsonv1.conf.extn.*;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.ca.certprofile.xijsonv1.conf.type.V1GeneralNameType;
import org.xipki.ca.certprofile.xijsonv1.conf.type.V1SubjectKeyIdentifierControl;
import org.xipki.security.KeySpec;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.codec.TripleState;

import java.util.Collection;

/**
 * Extension configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class V1ExtensionType {

  private final DescribableOid type;

  /**
   * Critical will be considered if both values (true and false) are allowed,
   * otherwise it will be ignored.
   */
  private final Boolean critical;

  private final Boolean required;

  @Deprecated
  private Boolean permittedInRequest;

  private TripleState inRequest;

  private AuthorityInfoAccess authorityInfoAccess;

  private V1SubjectKeyIdentifierControl subjectKeyIdentifier;

  private BasicConstraints basicConstraints;

  private V1BiometricInfo biometricInfo;

  private V1CertificatePolicies certificatePolicies;

  /**
   * For constant encoded Extension.
   */
  private V1ConstantExtnValue constant;

  private V1ExtendedKeyUsage extendedKeyUsage;

  private InhibitAnyPolicy inhibitAnyPolicy;

  private V1KeyUsages keyUsage;

  /**
   * Only for CA, at least one of permittedSubtrees and excludedSubtrees must
   * be present.
   */
  private V1NameConstraints nameConstraints;

  /**
   * Only for CA.
   */
  private V1PolicyMappings policyMappings;

  private PrivateKeyUsagePeriod privateKeyUsagePeriod;

  private PolicyConstraints policyConstraints;

  private V1QcStatements qcStatements;

  private V1SmimeCapabilities smimeCapabilities;

  private V1GeneralNameType subjectAltName;

  private V1SubjectInfoAccess subjectInfoAccess;

  private V1TlsFeature tlsFeature;

  private CCCSimpleExtensionSchema cccExtensionSchema;

  private CCCInstanceCAExtensionSchema cccInstanceCAExtensionSchema;

  public V1ExtensionType(DescribableOid type, Boolean critical,
                         Boolean required) {
    this.type = Args.notNull(type, "type");
    this.critical = critical;
    this.required = required;
  }

  public DescribableOid type() {
    return type;
  }

  // do not encode the default value.
  public Boolean critical() {
    return critical;
  }

  // do not encode the default value.
  public Boolean required() {
    return required;
  }

  @Deprecated
  public void setPermittedInRequest(boolean permittedInRequest) {
    this.permittedInRequest = permittedInRequest;
  }

  public void setInRequest(TripleState inRequest) {
    this.inRequest = inRequest;
  }

  public void setAuthorityInfoAccess(
      AuthorityInfoAccess authorityInfoAccess) {
    this.authorityInfoAccess = authorityInfoAccess;
  }

  public void setAuthorityKeyIdentifier(Object authorityKeyIdentifier) {
  }

  public void setSubjectKeyIdentifier(
      V1SubjectKeyIdentifierControl subjectKeyIdentifier) {
    this.subjectKeyIdentifier = subjectKeyIdentifier;
  }

  @Deprecated
  public void setBasicConstrains(BasicConstraints basicConstraints) {
    setBasicConstraints(basicConstraints);
  }

  public void setBasicConstraints(BasicConstraints basicConstraints) {
    this.basicConstraints = basicConstraints;
  }

  public void setBiometricInfo(V1BiometricInfo biometricInfo) {
    this.biometricInfo = biometricInfo;
  }

  public void setCertificatePolicies(
      V1CertificatePolicies certificatePolicies) {
    this.certificatePolicies = certificatePolicies;
  }

  public V1ConstantExtnValue constant() {
    return constant;
  }

  public void setConstant(V1ConstantExtnValue constant) {
    this.constant = constant;
  }

  public void setCrlDistributionPoints(Object crlDistributionPoints) {
  }

  public void setExtendedKeyUsage(V1ExtendedKeyUsage extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
  }

  public void setFreshestCrl(Object freshestCrl) {
  }

  public void setInhibitAnyPolicy(InhibitAnyPolicy inhibitAnyPolicy) {
    this.inhibitAnyPolicy = inhibitAnyPolicy;
  }

  public V1KeyUsages keyUsage() {
    return keyUsage;
  }

  public void setKeyUsage(V1KeyUsages keyUsage) {
    this.keyUsage = keyUsage;
  }

  public void setNameConstraints(V1NameConstraints nameConstraints) {
    this.nameConstraints = nameConstraints;
  }

  public void setPolicyMappings(V1PolicyMappings policyMappings) {
    this.policyMappings = policyMappings;
  }

  public void setPrivateKeyUsagePeriod(
      PrivateKeyUsagePeriod privateKeyUsagePeriod) {
    this.privateKeyUsagePeriod = privateKeyUsagePeriod;
  }

  public void setPolicyConstraints(PolicyConstraints policyConstraints) {
    this.policyConstraints = policyConstraints;
  }

  public void setQcStatements(V1QcStatements qcStatements) {
    this.qcStatements = qcStatements;
  }

  public void setSmimeCapabilities(V1SmimeCapabilities smimeCapabilities) {
    this.smimeCapabilities = smimeCapabilities;
  }

  public void setSubjectAltName(V1GeneralNameType subjectAltName) {
    this.subjectAltName = subjectAltName;
  }

  public void setSubjectInfoAccess(V1SubjectInfoAccess subjectInfoAccess) {
    this.subjectInfoAccess = subjectInfoAccess;
  }

  public void setTlsFeature(V1TlsFeature tlsFeature) {
    this.tlsFeature = tlsFeature;
  }

  public void setCccExtensionSchema(
      CCCSimpleExtensionSchema cccExtensionSchema) {
    this.cccExtensionSchema = cccExtensionSchema;
  }

  public void setCccInstanceCAExtensionSchema(
      CCCInstanceCAExtensionSchema cccInstanceCAExtensionSchema) {
    this.cccInstanceCAExtensionSchema = cccInstanceCAExtensionSchema;
  }

  public void setPermittedInRequest(Boolean permittedInRequest) {
    this.permittedInRequest = permittedInRequest;
  }

  // TODO: remove parameter keySpecs
  public ExtensionType toV2(Collection<KeySpec> keySpecs)
      throws CertprofileException {
    ExtensionType v2 = new ExtensionType(
        ExtensionID.ofOid(type.oid()), critical, required);

    v2.setAuthorityInfoAccess(authorityInfoAccess);

    // authorityKeyIdentifier: not needed in V2

    if (basicConstraints != null) {
      v2.setBasicConstraints(basicConstraints);
    }

    if (biometricInfo != null) {
      v2.setBiometricInfo(biometricInfo.toV2());
      inRequest = TripleState.required;
    }

    if (certificatePolicies != null) {
      v2.setCertificatePolicies(certificatePolicies.toV2());
    }

    if (constant != null) {
      v2.setConstant(constant.toV2());
    }

    if (extendedKeyUsage != null) {
      v2.setExtendedKeyUsage(extendedKeyUsage.toV2());
    }

    if (inhibitAnyPolicy != null) {
      v2.setInhibitAnyPolicy(inhibitAnyPolicy);
    }

    if (keyUsage != null) {
      v2.setKeyUsage(keyUsage.toV2(keySpecs));
    }

    if (nameConstraints != null) {
      v2.setNameConstraints(nameConstraints.toV2());
      inRequest = TripleState.required;
    }

    if (policyMappings != null) {
      v2.setPolicyMappings(policyMappings.toV2());
    }

    if (privateKeyUsagePeriod != null) {
      v2.setPrivateKeyUsagePeriod(privateKeyUsagePeriod);
      inRequest = TripleState.forbidden;
    }

    if (policyConstraints != null) {
      v2.setPolicyConstraints(policyConstraints);
    }

    if (qcStatements != null) {
      v2.setQcStatements(qcStatements.toV2());
    }

    if (smimeCapabilities != null) {
      v2.setSmimeCapabilities(smimeCapabilities.toV2());
    }

    if (subjectAltName != null) {
      v2.setSubjectAltName(subjectAltName.toV2());
    }

    if (subjectInfoAccess != null) {
      v2.setSubjectInfoAccess(subjectInfoAccess.toV2());
    }

    if (subjectKeyIdentifier != null) {
      v2.setSubjectKeyIdentifier(subjectKeyIdentifier.toV2());
    }

    if (tlsFeature != null) {
      v2.setTlsFeature(tlsFeature.toV2());
    }

    if (cccExtensionSchema != null) {
      v2.setCccExtensionSchema(cccExtensionSchema);
    }

    if (cccInstanceCAExtensionSchema != null) {
      v2.setCccInstanceCAExtensionSchema(cccInstanceCAExtensionSchema);
    }

    if (inRequest != null) {
      v2.setInRequest(inRequest);
    } else if (permittedInRequest != null) {
      v2.setInRequest(permittedInRequest ? TripleState.optional
          : TripleState.forbidden);
    }

    return v2;
  }

  public static V1ExtensionType parse(JsonMap json) throws CodecException {
    boolean required = json.getBool("required", false);
    if (required) {
      String[] unsupportedFields = {"additionalInformation",
          "admissionSyntax", "custom", "restriction",
          "subjectDirectoryAttributs", "validityModel"};
      for (String fieldName : unsupportedFields) {
        if (json.hasObject(fieldName)) {
          throw new CodecException("extension field " + fieldName +
              " is required but not supported");
        }
      }
    }

    V1ExtensionType ret = new V1ExtensionType(
        DescribableOid.parseNn(json, "type"),
        json.getBool("critical"),
        json.getBool("required"));

    TripleState inRequest = json.getEnum("inRequest", TripleState.class);
    if (inRequest == null) {
      Boolean b = json.getBool("permittedInRequest");
      if (b != null) {
        inRequest = b ? TripleState.optional : TripleState.forbidden;
      }
    }

    if (inRequest != null) {
      ret.setInRequest(inRequest);
    }

    JsonMap map = json.getMap("authorityInfoAccess");
    if (map != null) {
      ret.setAuthorityInfoAccess(AuthorityInfoAccess.parse(map));
    }

    map = json.getMap("subjectKeyIdentifier");
    if (map != null) {
      ret.setSubjectKeyIdentifier(V1SubjectKeyIdentifierControl.parse(map));
    }

    map = json.getMap("basicConstraints");
    if (map != null) {
      ret.setBasicConstraints(BasicConstraints.parse(map));
    }

    map = json.getMap("biometricInfo");
    if (map != null) {
      ret.setBiometricInfo(V1BiometricInfo.parse(map));
    }

    map = json.getMap("certificatePolicies");
    if (map != null) {
      ret.setCertificatePolicies(V1CertificatePolicies.parse(map));
    }

    map = json.getMap("constant");
    if (map != null) {
      ret.setConstant(V1ConstantExtnValue.parse(map));
    }

    map = json.getMap("extendedKeyUsage");
    if (map != null) {
      ret.setExtendedKeyUsage(V1ExtendedKeyUsage.parse(map));
    }

    map = json.getMap("inhibitAnyPolicy");
    if (map != null) {
      ret.setInhibitAnyPolicy(InhibitAnyPolicy.parse(map));
    }

    map = json.getMap("keyUsage");
    if (map != null) {
      ret.setKeyUsage(V1KeyUsages.parse(map));
    }

    map = json.getMap("nameConstraints");
    if (map != null) {
      ret.setNameConstraints(V1NameConstraints.parse(map));
    }

    map = json.getMap("policyMappings");
    if (map != null) {
      ret.setPolicyMappings(V1PolicyMappings.parse(map));
    }

    map = json.getMap("privateKeyUsagePeriod");
    if (map != null) {
      ret.setPrivateKeyUsagePeriod(PrivateKeyUsagePeriod.parse(map));
    }

    map = json.getMap("policyConstraints");
    if (map != null) {
      ret.setPolicyConstraints(PolicyConstraints.parse(map));
    }

    map = json.getMap("qcStatements");
    if (map != null) {
      ret.setQcStatements(V1QcStatements.parse(map));
    }

    map = json.getMap("smimeCapabilities");
    if (map != null) {
      ret.setSmimeCapabilities(V1SmimeCapabilities.parse(map));
    }

    map = json.getMap("subjectAltName");
    if (map != null) {
      ret.setSubjectAltName(V1GeneralNameType.parse(map));
    }

    map = json.getMap("subjectInfoAccess");
    if (map != null) {
      ret.setSubjectInfoAccess(V1SubjectInfoAccess.parse(map));
    }

    map = json.getMap("tlsFeature");
    if (map != null) {
      ret.setTlsFeature(V1TlsFeature.parse(map));
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
