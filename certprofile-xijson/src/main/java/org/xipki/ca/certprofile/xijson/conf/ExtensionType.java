/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.xipki.ca.api.profile.Certprofile.ExtKeyUsageControl;
import org.xipki.ca.api.profile.Certprofile.KeyUsageControl;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.certprofile.xijson.AdmissionExtension;
import org.xipki.ca.certprofile.xijson.CertificatePolicyInformation;
import org.xipki.ca.certprofile.xijson.CertificatePolicyQualifier;
import org.xipki.ca.certprofile.xijson.DirectoryStringType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicyInformationType.PolicyQualfierType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicyInformationType.PolicyQualifier;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableBinary;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.security.X509ExtensionType.ConstantExtnValue;
import org.xipki.security.X509ExtensionType.FieldType;
import org.xipki.security.X509ExtensionType.Tag;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.InvalidConfException;
import org.xipki.util.StringUtil;
import org.xipki.util.TripleState;
import org.xipki.util.ValidatableConf;

import com.alibaba.fastjson.annotation.JSONField;

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
  private boolean critical;

  @JSONField(ordinal = 3)
  private boolean required;

  @JSONField(ordinal = 4)
  private boolean permittedInRequest;

  @JSONField(ordinal = 5)
  private AdditionalInformation additionalInformation;

  @JSONField(ordinal = 5)
  private AdmissionSyntax admissionSyntax;

  @JSONField(ordinal = 5)
  private AuthorityInfoAccess authorityInfoAccess;

  @JSONField(ordinal = 5)
  private AuthorityKeyIdentifier authorityKeyIdentifier;

  @JSONField(ordinal = 5)
  private AuthorizationTemplate authorizationTemplate;

  @JSONField(ordinal = 5)
  private BasicConstraints basicConstrains;

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

  public boolean isCritical() {
    return critical;
  }

  public void setCritical(boolean critical) {
    this.critical = critical;
  }

  public boolean isRequired() {
    return required;
  }

  public void setRequired(boolean required) {
    this.required = required;
  }

  public boolean isPermittedInRequest() {
    return permittedInRequest;
  }

  public void setPermittedInRequest(boolean permittedInRequest) {
    this.permittedInRequest = permittedInRequest;
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

  public AuthorizationTemplate getAuthorizationTemplate() {
    return authorizationTemplate;
  }

  public void setAuthorizationTemplate(AuthorizationTemplate authorizationTemplate) {
    this.authorizationTemplate = authorizationTemplate;
  }

  public BasicConstraints getBasicConstrains() {
    return basicConstrains;
  }

  public void setBasicConstrains(BasicConstraints basicConstrains) {
    this.basicConstrains = basicConstrains;
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
    validate(type);
    validate(additionalInformation);
    validate(admissionSyntax);
    validate(authorityInfoAccess);
    validate(authorityKeyIdentifier);
    validate(authorizationTemplate);
    validate(basicConstrains);
    validate(biometricInfo);
    validate(certificatePolicies);
    validate(constant);
    validate(extendedKeyUsage);
    validate(inhibitAnyPolicy);
    validate(keyUsage);
    validate(nameConstraints);
    validate(policyMappings);
    validate(privateKeyUsagePeriod);
    validate(policyConstraints);
    validate(qcStatements);
    validate(restriction);
    validate(smimeCapabilities);
    validate(subjectAltName);
    validate(subjectDirectoryAttributs);
    validate(subjectInfoAccess);
    validate(tlsFeature);
    validate(validityModel);
    validate(syntax);
  } // method validate

  public static class AdditionalInformation extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DirectoryStringType type;

    @JSONField(ordinal = 2)
    private String text;

    public DirectoryStringType getType() {
      return type;
    }

    public void setType(DirectoryStringType type) {
      this.type = type;
    }

    public String getText() {
      return text;
    }

    public void setText(String text) {
      this.text = text;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(text, "text");
      notNull(type, "type");
    }

  } // class AdditionalInformation

  public static class AdmissionsType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private byte[] admissionAuthority;

    @JSONField(ordinal = 2)
    private NamingAuthorityType namingAuthority;

    @JSONField(ordinal = 3)
    private List<ProfessionInfoType> professionInfos;

    public byte[] getAdmissionAuthority() {
      return admissionAuthority;
    }

    public void setAdmissionAuthority(byte[] admissionAuthority) {
      this.admissionAuthority = admissionAuthority;
    }

    public NamingAuthorityType getNamingAuthority() {
      return namingAuthority;
    }

    public void setNamingAuthority(NamingAuthorityType namingAuthority) {
      this.namingAuthority = namingAuthority;
    }

    public List<ProfessionInfoType> getProfessionInfos() {
      if (professionInfos == null) {
        professionInfos = new LinkedList<>();
      }
      return professionInfos;
    }

    public void setProfessionInfos(List<ProfessionInfoType> professionInfos) {
      this.professionInfos = professionInfos;
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(namingAuthority);
      notEmpty(professionInfos, "professionInfos");
      validate(professionInfos);
    }

  } // class AdmissionsType

  public static class AdmissionSyntax extends ValidatableConf {

    @JSONField(ordinal = 1)
    private byte[] admissionAuthority;

    @JSONField(ordinal = 2)
    private List<AdmissionsType> contentsOfAdmissions;

    public byte[] getAdmissionAuthority() {
      return admissionAuthority;
    }

    public void setAdmissionAuthority(byte[] admissionAuthority) {
      this.admissionAuthority = admissionAuthority;
    }

    public List<AdmissionsType> getContentsOfAdmissions() {
      if (contentsOfAdmissions == null) {
        contentsOfAdmissions = new LinkedList<>();
      }
      return contentsOfAdmissions;
    }

    public void setContentsOfAdmissions(List<AdmissionsType> contentsOfAdmissions) {
      this.contentsOfAdmissions = contentsOfAdmissions;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(contentsOfAdmissions, "contentsOfAdmissions");
      validate(contentsOfAdmissions);
    }

    public AdmissionExtension.AdmissionSyntaxOption toXiAdmissionSyntax(boolean critical)
        throws CertprofileException {
      List<AdmissionExtension.AdmissionsOption> admissionsList = new LinkedList<>();
      for (AdmissionsType at : getContentsOfAdmissions()) {
        List<AdmissionExtension.ProfessionInfoOption> professionInfos = new LinkedList<>();
        for (ProfessionInfoType pi : at.getProfessionInfos()) {
          NamingAuthority namingAuthorityL3 = null;
          if (pi.getNamingAuthority() != null) {
            namingAuthorityL3 = buildNamingAuthority(pi.getNamingAuthority());
          }

          List<DescribableOid> oidTypes = pi.getProfessionOids();
          List<ASN1ObjectIdentifier> oids = null;
          if (CollectionUtil.isNotEmpty(oidTypes)) {
            oids = new LinkedList<>();
            for (DescribableOid k : oidTypes) {
              oids.add(new ASN1ObjectIdentifier(k.getOid()));
            }
          }

          RegistrationNumber rnType = pi.getRegistrationNumber();
          AdmissionExtension.RegistrationNumberOption rno = (rnType == null) ? null
              : new AdmissionExtension.RegistrationNumberOption(
                      rnType.getRegex(), rnType.getConstant());

          AdmissionExtension.ProfessionInfoOption pio =
              new AdmissionExtension.ProfessionInfoOption(namingAuthorityL3,
                  pi.getProfessionItems(), oids, rno, pi.getAddProfessionInfo());

          professionInfos.add(pio);
        }

        GeneralName admissionAuthority = null;
        if (at.getNamingAuthority() != null) {
          admissionAuthority = GeneralName.getInstance(
              asn1PrimitivefromByteArray(at.getAdmissionAuthority()));
        }

        NamingAuthority namingAuthority = null;
        if (at.getNamingAuthority() != null) {
          namingAuthority = buildNamingAuthority(at.getNamingAuthority());
        }

        AdmissionExtension.AdmissionsOption admissionsOption =
            new AdmissionExtension.AdmissionsOption(
                admissionAuthority, namingAuthority, professionInfos);
        admissionsList.add(admissionsOption);
      }

      GeneralName tmpAdmissionAuthority = null;
      if (admissionAuthority != null) {
        tmpAdmissionAuthority = GeneralName.getInstance(admissionAuthority);
      }

      return new AdmissionExtension.AdmissionSyntaxOption(
                  critical, tmpAdmissionAuthority, admissionsList);
    } // method toXiAdmissionSyntax

    private static ASN1Primitive asn1PrimitivefromByteArray(byte[] encoded)
        throws CertprofileException {
      try {
        return ASN1Primitive.fromByteArray(encoded);
      } catch (IOException ex) {
        throw new CertprofileException(ex.getMessage(), ex);
      }
    }

    private static NamingAuthority buildNamingAuthority(NamingAuthorityType value) {
      ASN1ObjectIdentifier oid = (value.getOid() == null) ? null
          : new ASN1ObjectIdentifier(value.getOid().getOid());
      String url = StringUtil.isBlank(value.getUrl()) ? null : value.getUrl();
      DirectoryString text = StringUtil.isBlank(value.getText()) ? null
          : new DirectoryString(value.getText());
      return new NamingAuthority(oid, url, text);
    } // method buildNamingAuthority

  } // class AdmissionSyntax

  public static class AuthorityInfoAccess extends ValidatableConf {

    @JSONField(ordinal = 1)
    private boolean includeCaIssuers;

    @JSONField(ordinal = 2)
    private boolean includeOcsp;

    @JSONField(ordinal = 3)
    private Set<String> ocspProtocols;

    @JSONField(ordinal = 3)
    private Set<String> caIssuersProtocols;

    public boolean isIncludeCaIssuers() {
      return includeCaIssuers;
    }

    public void setIncludeCaIssuers(boolean includeCaIssuers) {
      this.includeCaIssuers = includeCaIssuers;
    }

    public boolean isIncludeOcsp() {
      return includeOcsp;
    }

    public void setIncludeOcsp(boolean includeOcsp) {
      this.includeOcsp = includeOcsp;
    }

    public Set<String> getOcspProtocols() {
      return ocspProtocols;
    }

    public void setOcspProtocols(Set<String> ocspProtocols) {
      this.ocspProtocols = ocspProtocols;
    }

    public Set<String> getCaIssuersProtocols() {
      return caIssuersProtocols;
    }

    public void setCaIssuersProtocols(Set<String> caIssuersProtocols) {
      this.caIssuersProtocols = caIssuersProtocols;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class AuthorityInfoAccess

  public static class AuthorityKeyIdentifier extends ValidatableConf {

    private boolean useIssuerAndSerial;

    public boolean isUseIssuerAndSerial() {
      return useIssuerAndSerial;
    }

    public void setUseIssuerAndSerial(boolean useIssuerAndSerial) {
      this.useIssuerAndSerial = useIssuerAndSerial;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class AuthorityKeyIdentifier

  public static class AuthorizationTemplate extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableOid type;

    @JSONField(ordinal = 2)
    private DescribableBinary accessRights;

    public DescribableOid getType() {
      return type;
    }

    public void setType(DescribableOid type) {
      this.type = type;
    }

    public DescribableBinary getAccessRights() {
      return accessRights;
    }

    public void setAccessRights(DescribableBinary accessRights) {
      this.accessRights = accessRights;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(type, "type");
      validate(type);
      notNull(accessRights, "accessRights");
      validate(accessRights);
    }

  } // class AuthorizationTemplate

  public static class BasicConstraints extends ValidatableConf {

    private int pathLen;

    public int getPathLen() {
      return pathLen;
    }

    public void setPathLen(int pathLen) {
      this.pathLen = pathLen;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class BasicConstraints

  public static class BiometricInfo extends ValidatableConf {

    @JSONField(ordinal = 1)
    private List<BiometricTypeType> types;

    @JSONField(ordinal = 2)
    private List<DescribableOid> hashAlgorithms;

    @JSONField(ordinal = 3)
    private TripleState includeSourceDataUri;

    public List<BiometricTypeType> getTypes() {
      if (types == null) {
        types = new LinkedList<>();
      }
      return types;
    }

    public void setTypes(List<BiometricTypeType> types) {
      this.types = types;
    }

    public List<DescribableOid> getHashAlgorithms() {
      if (hashAlgorithms == null) {
        hashAlgorithms = new LinkedList<>();
      }
      return hashAlgorithms;
    }

    public void setHashAlgorithms(List<DescribableOid> hashAlgorithms) {
      this.hashAlgorithms = hashAlgorithms;
    }

    public TripleState getIncludeSourceDataUri() {
      return includeSourceDataUri;
    }

    public void setIncludeSourceDataUri(TripleState includeSourceDataUri) {
      this.includeSourceDataUri = includeSourceDataUri;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(hashAlgorithms, "hashAlgorithms");
      notEmpty(types, "types");
      notNull(includeSourceDataUri, "includeSourceDataUri");
    }

  } // class BiometricInfo

  public static class BiometricTypeType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableInt predefined;

    @JSONField(ordinal = 2)
    private DescribableOid oid;

    public DescribableInt getPredefined() {
      return predefined;
    }

    public void setPredefined(DescribableInt predefined) {
      this.predefined = predefined;
    }

    public DescribableOid getOid() {
      return oid;
    }

    public void setOid(DescribableOid oid) {
      this.oid = oid;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(oid, "oid");
      notNull(predefined, "predefined");
    }

  } // class BiometricTypeType

  public static class CertificatePolicies extends ValidatableConf {

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
    public void validate() throws InvalidConfException {
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

  public static class CrlDistributionPoints extends ValidatableConf {

    private Set<String> protocols;

    public Set<String> getProtocols() {
      return protocols;
    }

    public void setProtocols(Set<String> protocols) {
      this.protocols = protocols;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class CrlDistributionPoints

  public static class ExtendedKeyUsage extends ValidatableConf {

    private List<ExtendedKeyUsage.Usage> usages;

    public List<ExtendedKeyUsage.Usage> getUsages() {
      if (usages == null) {
        usages = new LinkedList<>();
      }
      return usages;
    }

    public void setUsages(List<ExtendedKeyUsage.Usage> usages) {
      this.usages = usages;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(usages, "usages");
      validate(usages);
    }

    public Set<ExtKeyUsageControl> toXiExtKeyUsageOptions() {
      List<ExtendedKeyUsage.Usage> usages = getUsages();
      Set<ExtKeyUsageControl> controls = new HashSet<>();

      for (ExtendedKeyUsage.Usage m : usages) {
        controls.add(new ExtKeyUsageControl(
                      new ASN1ObjectIdentifier(m.getOid()), m.isRequired()));
      }

      return Collections.unmodifiableSet(controls);
    } // method buildExtKeyUsageOptions

    public static class Usage extends DescribableOid {

      private boolean required;

      public boolean isRequired() {
        return required;
      }

      public void setRequired(boolean required) {
        this.required = required;
      }

    } // class Usage

  } // class ExtendedKeyUsage

  public static class ExtnSyntax extends Describable {

    @JSONField(ordinal = 1)
    private FieldType type;

    /**
     * Will be considered if the type is one of TeletexString, PrintableString, UTF8String and
     * BMPString.
     */
    @JSONField(ordinal = 3)
    private String stringRegex;

    @JSONField(ordinal = 4)
    private Tag tag;

    @JSONField(ordinal = 5)
    private List<SubFieldSyntax> subFields;

    @JSONField(name = "type")
    public String getTypeText() {
      return type.getText();
    }

    // for the JSON deserializer
    private ExtnSyntax() {
    }

    public ExtnSyntax(FieldType type) {
      this.type = Args.notNull(type, "type");
    }

    @JSONField(name = "type")
    public void setTypeText(String text) {
      if (text == null) {
        this.type = null;
      } else {
        this.type = null;
        for (FieldType m : FieldType.values()) {
          if (m.name().equalsIgnoreCase(text) || m.getText().equalsIgnoreCase(text)) {
            this.type = m;
          }
        }

        if (type == null) {
          throw new IllegalArgumentException("invalid type " + type);
        }
      }
    } // method setTypeText

    public FieldType type() {
      return type;
    }

    public Tag getTag() {
      return tag;
    }

    public void setTag(Tag tag) {
      this.tag = tag;
    }

    public String getStringRegex() {
      return stringRegex;
    }

    public void setStringRegex(String stringRegex) {
      if (StringUtil.isNotBlank(stringRegex)) {
        this.stringRegex = stringRegex;
      } else {
        this.stringRegex = null;
      }
    } // method setStringRegex

    public List<SubFieldSyntax> getSubFields() {
      return subFields;
    }

    public void setSubFields(List<SubFieldSyntax> subFields) {
      this.subFields = subFields;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(type, "type");
      if (CollectionUtil.isNotEmpty(subFields)) {
        if (type == FieldType.SEQUENCE || type == FieldType.SET) {
          for (SubFieldSyntax m : subFields) {
            m.validate();
          }
        } else if (type == FieldType.SEQUENCE_OF || type == FieldType.SET_OF) {
          // the fields will be considered as the subfields of CHOICE, make sure that
          // two subfields of same type have different tag
          Set<String> set = new HashSet<>();
          for (SubFieldSyntax m : subFields) {
            if (m.isRequired()) {
              throw new InvalidConfException(
                  "SubField within SEQUECE_OF or SET OF must not be required");
            }

            int tag = (m.getTag() != null) ? m.getTag().getValue() : -1;
            if (!set.add(m.type() + "-" + tag)) {
              throw new InvalidConfException("multiple " + m.type()
                  + " of the same tag (or no tag) within " + type + " defined");
            }

            m.validate();
          }
        } else {
          throw new InvalidConfException("unsupported type " + type);
        }
      }
    } // method validate

    public static class SubFieldSyntax extends ExtnSyntax {

      private boolean required;

      // for the JSON deserializer
      @SuppressWarnings("unused")
      private SubFieldSyntax() {
      }

      public SubFieldSyntax(FieldType type) {
        super(type);
      }

      public boolean isRequired() {
        return required;
      }

      public void setRequired(boolean required) {
        this.required = required;
      }

      @Override
      public void validate() throws InvalidConfException {
        super.validate();
        if (FieldType.RAW == type()) {
          throw new InvalidConfException("FieldType RAW is not allowed");
        }
      }

    } // class SubFieldSyntax

  } // class ExtnSyntax

  public static class InhibitAnyPolicy extends ValidatableConf {

    private int skipCerts;

    public int getSkipCerts() {
      return skipCerts;
    }

    public void setSkipCerts(int skipCerts) {
      this.skipCerts = skipCerts;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class InhibitAnyPolicy

  public static class KeyUsage extends ValidatableConf {

    private List<KeyUsage.Usage> usages;

    public List<KeyUsage.Usage> getUsages() {
      if (usages == null) {
        usages = new LinkedList<>();
      }
      return usages;
    }

    public void setUsages(List<KeyUsage.Usage> usages) {
      this.usages = usages;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(usages, "usages");
      validate(usages);
    }

    public Set<KeyUsageControl> toXiKeyUsageOptions() {
      List<Usage> usages = getUsages();
      Set<KeyUsageControl> controls = new HashSet<>();

      for (ExtensionType.KeyUsage.Usage m : usages) {
        controls.add(new KeyUsageControl(m.getValue(), m.isRequired()));
      }

      return Collections.unmodifiableSet(controls);
    } // method toXiKeyUsageOptions

    public static class Usage extends ValidatableConf {

      private org.xipki.security.KeyUsage value;

      private boolean required;

      public org.xipki.security.KeyUsage getValue() {
        return value;
      }

      public void setValue(org.xipki.security.KeyUsage value) {
        this.value = value;
      }

      public boolean isRequired() {
        return required;
      }

      public void setRequired(boolean required) {
        this.required = required;
      }

      @Override
      public void validate() throws InvalidConfException {
      }

    } // class Usage

  } // class KeyUsage

  /**
   * Only for CA, at least one of permittedSubtrees and excludedSubtrees must be present.
   *
   */
  public static class NameConstraints extends ValidatableConf {

    @JSONField(ordinal = 1)
    private List<GeneralSubtreeType> permittedSubtrees;

    @JSONField(ordinal = 2)
    private List<GeneralSubtreeType> excludedSubtrees;

    public List<GeneralSubtreeType> getPermittedSubtrees() {
      if (permittedSubtrees == null) {
        permittedSubtrees = new LinkedList<>();
      }
      return permittedSubtrees;
    }

    public void setPermittedSubtrees(List<GeneralSubtreeType> permittedSubtrees) {
      this.permittedSubtrees = permittedSubtrees;
    }

    public List<GeneralSubtreeType> getExcludedSubtrees() {
      if (excludedSubtrees == null) {
        excludedSubtrees = new LinkedList<>();
      }
      return excludedSubtrees;
    }

    public void setExcludedSubtrees(List<GeneralSubtreeType> excludedSubtrees) {
      this.excludedSubtrees = excludedSubtrees;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (CollectionUtil.isEmpty(permittedSubtrees) && CollectionUtil.isEmpty(excludedSubtrees)) {
        throw new InvalidConfException(
            "permittedSubtrees and excludedSubtrees may not be both null");
      }
      validate(permittedSubtrees);
      validate(excludedSubtrees);
    } // method validate

    public org.bouncycastle.asn1.x509.NameConstraints toXiNameConstrains()
        throws CertprofileException {
      GeneralSubtree[] permitted = buildGeneralSubtrees(getPermittedSubtrees());
      GeneralSubtree[] excluded = buildGeneralSubtrees(getExcludedSubtrees());
      return (permitted == null && excluded == null) ? null
          : new org.bouncycastle.asn1.x509.NameConstraints(permitted, excluded);
    } // method toXiNameConstrains

    private static GeneralSubtree[] buildGeneralSubtrees(List<GeneralSubtreeType> subtrees)
        throws CertprofileException {
      if (CollectionUtil.isEmpty(subtrees)) {
        return null;
      }

      final int n = subtrees.size();
      GeneralSubtree[] ret = new GeneralSubtree[n];
      for (int i = 0; i < n; i++) {
        ret[i] = buildGeneralSubtree(subtrees.get(i));
      }

      return ret;
    } // method buildGeneralSubtrees

    private static GeneralSubtree buildGeneralSubtree(GeneralSubtreeType type)
        throws CertprofileException {
      Args.notNull(type, "type");
      GeneralSubtreeType.Base baseType = type.getBase();
      GeneralName base = null;
      if (baseType.getDirectoryName() != null) {
        base = new GeneralName(X509Util.reverse(new X500Name(baseType.getDirectoryName())));
      } else if (baseType.getDnsName() != null) {
        base = new GeneralName(GeneralName.dNSName, baseType.getDnsName());
      } else if (baseType.getIpAddress() != null) {
        base = new GeneralName(GeneralName.iPAddress, baseType.getIpAddress());
      } else if (baseType.getRfc822Name() != null) {
        base = new GeneralName(GeneralName.rfc822Name, baseType.getRfc822Name());
      } else if (baseType.getUri() != null) {
        base = new GeneralName(GeneralName.uniformResourceIdentifier, baseType.getUri());
      } else {
        throw new IllegalStateException(
            "should not reach here, unknown child of GeneralSubtreeType");
      }

      Integer min = type.getMinimum();
      if (min != null && min < 0) {
        throw new CertprofileException("negative minimum is not allowed: " + min);
      }
      BigInteger minimum = (min == null) ? null : BigInteger.valueOf(min.intValue());

      Integer max = type.getMaximum();
      if (max != null && max < 0) {
        throw new CertprofileException("negative maximum is not allowed: " + max);
      }
      BigInteger maximum = (max == null) ? null : BigInteger.valueOf(max.intValue());

      return new GeneralSubtree(base, minimum, maximum);
    } // method buildGeneralSubtree

  } // class NameConstraints

  public static class NamingAuthorityType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableOid oid;

    @JSONField(ordinal = 2)
    private String url;

    @JSONField(ordinal = 3)
    private String text;

    public DescribableOid getOid() {
      return oid;
    }

    public void setOid(DescribableOid oid) {
      this.oid = oid;
    }

    public String getUrl() {
      return url;
    }

    public void setUrl(String url) {
      this.url = url;
    }

    public String getText() {
      return text;
    }

    public void setText(String text) {
      this.text = text;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (oid == null && url == null && text == null) {
        throw new InvalidConfException("oid, url and text may not be all null");
      }
      validate(oid);
    }

  } // class NamingAuthorityType

  public static class PolicyConstraints extends ValidatableConf {

    @JSONField(ordinal = 1)
    private Integer requireExplicitPolicy;

    @JSONField(ordinal = 2)
    private Integer inhibitPolicyMapping;

    public Integer getRequireExplicitPolicy() {
      return requireExplicitPolicy;
    }

    public void setRequireExplicitPolicy(Integer requireExplicitPolicy) {
      this.requireExplicitPolicy = requireExplicitPolicy;
    }

    public Integer getInhibitPolicyMapping() {
      return inhibitPolicyMapping;
    }

    public void setInhibitPolicyMapping(Integer inhibitPolicyMapping) {
      this.inhibitPolicyMapping = inhibitPolicyMapping;
    }

    @Override
    public void validate() throws InvalidConfException {
      // Only for CA, at least one of requireExplicitPolicy and inhibitPolicyMapping must be present
      if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
        throw new InvalidConfException(
            "requireExplicitPolicy and inhibitPolicyMapping may not be both null");
      }
    }

    public ASN1Sequence toXiPolicyConstrains() throws CertprofileException {
      if (requireExplicitPolicy != null && requireExplicitPolicy < 0) {
        throw new CertprofileException(
            "negative requireExplicitPolicy is not allowed: " + requireExplicitPolicy);
      }

      if (inhibitPolicyMapping != null && inhibitPolicyMapping < 0) {
        throw new CertprofileException(
            "negative inhibitPolicyMapping is not allowed: " + inhibitPolicyMapping);
      }

      if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
        return null;
      }

      final boolean explicit = false;
      ASN1EncodableVector vec = new ASN1EncodableVector();
      if (requireExplicitPolicy != null) {
        vec.add(new DERTaggedObject(explicit, 0,
            new ASN1Integer(BigInteger.valueOf(requireExplicitPolicy))));
      }

      if (inhibitPolicyMapping != null) {
        vec.add(new DERTaggedObject(explicit, 1,
            new ASN1Integer(BigInteger.valueOf(inhibitPolicyMapping))));
      }

      return new DERSequence(vec);
    } //method toXiPolicyConstrains

  } // class PolicyConstraints

  public static class PolicyIdMappingType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableOid issuerDomainPolicy;

    @JSONField(ordinal = 2)
    private DescribableOid subjectDomainPolicy;

    public DescribableOid getIssuerDomainPolicy() {
      return issuerDomainPolicy;
    }

    public void setIssuerDomainPolicy(DescribableOid issuerDomainPolicy) {
      this.issuerDomainPolicy = issuerDomainPolicy;
    }

    public DescribableOid getSubjectDomainPolicy() {
      return subjectDomainPolicy;
    }

    public void setSubjectDomainPolicy(DescribableOid subjectDomainPolicy) {
      this.subjectDomainPolicy = subjectDomainPolicy;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(issuerDomainPolicy, "issuerDomainPolicy");
      validate(issuerDomainPolicy);
      notNull(subjectDomainPolicy, "subjectDomainPolicy");
      validate(subjectDomainPolicy);
    }

  } // class PolicyIdMappingType

  /**
   * Only for CA.
   *
   */
  public static class PolicyMappings extends ValidatableConf {

    private List<PolicyIdMappingType> mappings;

    public List<PolicyIdMappingType> getMappings() {
      if (mappings == null) {
        mappings = new LinkedList<>();
      }
      return mappings;
    }

    public void setMappings(List<PolicyIdMappingType> mappings) {
      this.mappings = mappings;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(mappings, "mappings");
      validate(mappings);
    }

    public org.bouncycastle.asn1.x509.PolicyMappings toXiPolicyMappings() {
      List<PolicyIdMappingType> mappings = getMappings();
      final int n = mappings.size();

      CertPolicyId[] issuerDomainPolicy = new CertPolicyId[n];
      CertPolicyId[] subjectDomainPolicy = new CertPolicyId[n];

      for (int i = 0; i < n; i++) {
        PolicyIdMappingType mapping = mappings.get(i);
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(
            mapping.getIssuerDomainPolicy().getOid());
        issuerDomainPolicy[i] = CertPolicyId.getInstance(oid);

        oid = new ASN1ObjectIdentifier(mapping.getSubjectDomainPolicy().getOid());
        subjectDomainPolicy[i] = CertPolicyId.getInstance(oid);
      }

      return new org.bouncycastle.asn1.x509.PolicyMappings(issuerDomainPolicy, subjectDomainPolicy);
    } // method toXiPolicyMappings

  } // class PolicyMappings

  public static class PrivateKeyUsagePeriod extends ValidatableConf {

    private String validity;

    public String getValidity() {
      return validity;
    }

    public void setValidity(String validity) {
      this.validity = validity;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(validity, "validity");
    }

  } // class PrivateKeyUsagePeriod

  public static class ProfessionInfoType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private NamingAuthorityType namingAuthority;

    @JSONField(ordinal = 2)
    private List<DescribableOid> professionOids;

    @JSONField(ordinal = 3)
    private List<String> professionItems;

    @JSONField(ordinal = 4)
    private RegistrationNumber registrationNumber;

    @JSONField(ordinal = 5)
    private byte[] addProfessionInfo;

    public NamingAuthorityType getNamingAuthority() {
      return namingAuthority;
    }

    public void setNamingAuthority(NamingAuthorityType namingAuthority) {
      this.namingAuthority = namingAuthority;
    }

    public List<DescribableOid> getProfessionOids() {
      if (professionOids == null) {
        professionOids = new LinkedList<>();
      }
      return professionOids;
    }

    public void setProfessionOids(List<DescribableOid> professionOids) {
      this.professionOids = professionOids;
    }

    public List<String> getProfessionItems() {
      if (professionItems == null) {
        professionItems = new LinkedList<>();
      }
      return professionItems;
    }

    public void setProfessionItems(List<String> professionItems) {
      this.professionItems = professionItems;
    }

    public RegistrationNumber getRegistrationNumber() {
      return registrationNumber;
    }

    public void setRegistrationNumber(RegistrationNumber registrationNumber) {
      this.registrationNumber = registrationNumber;
    }

    public byte[] getAddProfessionInfo() {
      return addProfessionInfo;
    }

    public void setAddProfessionInfo(byte[] addProfessionInfo) {
      this.addProfessionInfo = addProfessionInfo;
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(namingAuthority);
      validate(professionOids);
      validate(registrationNumber);
    }

  } // class ProfessionInfoType

  public static class QcStatements extends ValidatableConf {

    private List<QcStatementType> qcStatements;

    public List<QcStatementType> getQcStatements() {
      if (qcStatements == null) {
        qcStatements = new LinkedList<>();
      }
      return qcStatements;
    }

    public void setQcStatements(List<QcStatementType> qcStatements) {
      this.qcStatements = qcStatements;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(qcStatements, "qcStatements");
      validate(qcStatements);
    }

  } // class QcStatements

  public static class RegistrationNumber extends ValidatableConf {

    @JSONField(ordinal = 1)
    private String regex;

    @JSONField(ordinal = 2)
    private String constant;

    public String getRegex() {
      return regex;
    }

    public void setRegex(String regex) {
      this.regex = regex;
    }

    public String getConstant() {
      return constant;
    }

    public void setConstant(String constant) {
      this.constant = constant;
    }

    @Override
    public void validate() throws InvalidConfException {
      exactOne(regex, "regex", constant, "constant");
    }

  } // class RegistrationNumber

  public static class Restriction extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DirectoryStringType type;

    @JSONField(ordinal = 2)
    private String text;

    public DirectoryStringType getType() {
      return type;
    }

    public void setType(DirectoryStringType type) {
      this.type = type;
    }

    public String getText() {
      return text;
    }

    public void setText(String text) {
      this.text = text;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(type, "type");
      notEmpty(text, "text");
    }

  } // class Restriction

  public static class SmimeCapabilities extends ValidatableConf {

    private List<SmimeCapability> capabilities;

    public List<SmimeCapability> getCapabilities() {
      if (capabilities == null) {
        capabilities = new LinkedList<>();
      }
      return capabilities;
    }

    public void setCapabilities(List<SmimeCapability> capabilities) {
      this.capabilities = capabilities;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(capabilities, "capabilities");
      validate(capabilities);
    }

  } // class SmimeCapabilities

  public static class SmimeCapability extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableOid capabilityId;

    @JSONField(ordinal = 2)
    private SmimeCapabilityParameter parameter;

    public DescribableOid getCapabilityId() {
      return capabilityId;
    }

    public void setCapabilityId(DescribableOid capabilityId) {
      this.capabilityId = capabilityId;
    }

    public SmimeCapabilityParameter getParameter() {
      return parameter;
    }

    public void setParameter(SmimeCapabilityParameter parameter) {
      this.parameter = parameter;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(capabilityId, "capabilityId");
      validate(capabilityId);
      validate(parameter);
    }

  } // class SmimeCapability

  public static class SmimeCapabilityParameter extends ValidatableConf {

    @JSONField(ordinal = 1)
    private BigInteger integer;

    @JSONField(ordinal = 2)
    private DescribableBinary binary;

    public BigInteger getInteger() {
      return integer;
    }

    public void setInteger(BigInteger integer) {
      this.integer = integer;
    }

    public DescribableBinary getBinary() {
      return binary;
    }

    public void setBinary(DescribableBinary binary) {
      this.binary = binary;
    }

    @Override
    public void validate() throws InvalidConfException {
      exactOne(integer, "integer", binary, "binary");
      validate(binary);
    }

  } // class SmimeCapabilityParameter

  public static class SubjectDirectoryAttributs extends ValidatableConf {

    private List<DescribableOid> types;

    public List<DescribableOid> getTypes() {
      if (types == null) {
        types = new LinkedList<>();
      }
      return types;
    }

    public void setTypes(List<DescribableOid> types) {
      this.types = types;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(types, "types");
      validate(types);
    }

  } // class SubjectDirectoryAttributs

  public static class SubjectInfoAccess extends ValidatableConf {

    private List<Access> accesses;

    public List<Access> getAccesses() {
      if (accesses == null) {
        accesses = new LinkedList<>();
      }
      return accesses;
    }

    public void setAccesses(List<Access> accesses) {
      this.accesses = accesses;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(accesses, "accesses");
      validate(accesses);
    }

    public static class Access extends ValidatableConf {

      @JSONField(ordinal = 1)
      private DescribableOid accessMethod;

      @JSONField(ordinal = 2)
      private GeneralNameType accessLocation;

      public DescribableOid getAccessMethod() {
        return accessMethod;
      }

      public void setAccessMethod(DescribableOid accessMethod) {
        this.accessMethod = accessMethod;
      }

      public GeneralNameType getAccessLocation() {
        return accessLocation;
      }

      public void setAccessLocation(GeneralNameType accessLocation) {
        this.accessLocation = accessLocation;
      }

      @Override
      public void validate() throws InvalidConfException {
        notNull(accessMethod, "accessMethod");
        validate(accessMethod);
        notNull(accessLocation, "accessLocation");
        validate(accessLocation);
      }

    } // class Access

  } // class SubjectInfoAccess

  public static class TlsFeature extends ValidatableConf {

    private List<DescribableInt> features;

    public List<DescribableInt> getFeatures() {
      if (features == null) {
        features = new LinkedList<>();
      }
      return features;
    }

    public void setFeatures(List<DescribableInt> features) {
      this.features = features;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(features, "features");
      validate(features);
    }

  } // class TlsFeature

  public static class ValidityModel extends ValidatableConf {

    private DescribableOid modelId;

    public DescribableOid getModelId() {
      return modelId;
    }

    public void setModelId(DescribableOid modelId) {
      this.modelId = modelId;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(modelId, "modelId");
      validate(modelId);
    }

  } // class ValidityModel

}
