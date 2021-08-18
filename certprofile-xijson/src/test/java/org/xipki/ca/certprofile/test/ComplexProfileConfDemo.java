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

package org.xipki.ca.certprofile.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.certprofile.xijson.DirectoryStringType;
import org.xipki.ca.certprofile.xijson.conf.*;
import org.xipki.ca.certprofile.xijson.conf.AdmissionSyntax.AdmissionsType;
import org.xipki.ca.certprofile.xijson.conf.AdmissionSyntax.NamingAuthorityType;
import org.xipki.ca.certprofile.xijson.conf.AdmissionSyntax.ProfessionInfoType;
import org.xipki.ca.certprofile.xijson.conf.AdmissionSyntax.RegistrationNumber;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies.CertificatePolicyInformationType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies.PolicyQualfierType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies.PolicyQualifier;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.ca.certprofile.xijson.conf.ExtnSyntax.SubFieldSyntax;
import org.xipki.ca.certprofile.xijson.conf.Subject.RdnType;
import org.xipki.ca.certprofile.xijson.conf.Subject.ValueType;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.TlsExtensionType;
import org.xipki.security.X509ExtensionType.FieldType;
import org.xipki.security.X509ExtensionType.Tag;

import java.util.*;

/**
 * Demo the creation of xijson configuration for complex certificates.
 *
 * @author Lijun Liao
 */

public class ComplexProfileConfDemo extends ProfileConfBuilder {

  public static class ExtnDemoWithConf {
    private List<String> texts;

    public List<String> getTexts() {
      return texts;
    }

    public void setTexts(List<String> texts) {
      this.texts = texts;
    }

  }

  public static void main(String[] args) {
    try {
      certprofileSubCaComplex("certprofile-subca-complex.json");
      certprofileEeComplex("certprofile-ee-complex.json");
      certprofileQc("certprofile-qc.json");
      certprofileMultipleOus("certprofile-multiple-ous.json");
      certprofileMultipleValuedRdn("certprofile-multi-valued-rdn.json");
      certprofileFixedPartialSubject("certprofile-fixed-partial-subject.json");
      certprofileConstantExt("certprofile-constant-ext.json");
      certprofileConstantExtImplicitTag("certprofile-constant-ext-implicit-tag.json");
      certprofileConstantExtExplicitTag("certprofile-constant-ext-explicit-tag.json");
      certprofileSyntaxExt("certprofile-syntax-ext.json");
      certprofileSyntaxExtImplicitTag("certprofile-syntax-ext-implicit-tag.json");
      certprofileSyntaxExtExplicitTag("certprofile-syntax-ext-explicit-tag.json");
      certprofileExtended("certprofile-extended.json");
      certprofileAppleWwdr("certprofile-apple-wwdr.json");
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void certprofileSubCaComplex(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile subca-complex (with most extensions)",
        CertLevel.SubCA, "8y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1, null, "PREFIX ", " SUFFIX"));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));
    last(list).setBasicConstrains(createBasicConstraints(1));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign},
        null));

    // Certificate Policies
    list.add(createExtension(Extension.certificatePolicies, true, false));

    Map<ASN1ObjectIdentifier, String> policies = new HashMap<>();
    policies.put(new ASN1ObjectIdentifier("1.2.3.4.5"), "http://myorg.org/ca1-cps");
    policies.put(new ASN1ObjectIdentifier("2.4.3.2.1"), null);
    last(list).setCertificatePolicies(createCertificatePolicies(policies));

    // Policy Mappings
    list.add(createExtension(Extension.policyMappings, true, true));
    last(list).setPolicyMappings(new PolicyMappings());
    last(list).getPolicyMappings().getMappings().add(
        createPolicyIdMapping(new ASN1ObjectIdentifier("1.1.1.1.1"),
            new ASN1ObjectIdentifier("2.1.1.1.1")));
    last(list).getPolicyMappings().getMappings().add(
        createPolicyIdMapping(new ASN1ObjectIdentifier("1.1.1.1.2"),
            new ASN1ObjectIdentifier("2.1.1.1.2")));

    // Policy Constraints
    list.add(createExtension(Extension.policyConstraints, true, true));
    last(list).setPolicyConstraints(createPolicyConstraints(2, 2));

    // Name Constrains
    list.add(createExtension(Extension.nameConstraints, true, true));
    last(list).setNameConstraints(createNameConstraints());

    // Inhibit anyPolicy
    list.add(createExtension(Extension.inhibitAnyPolicy, true, true));
    last(list).setInhibitAnyPolicy(createInhibitAnyPolicy(1));

    // SubjectAltName
    list.add(createExtension(Extension.subjectAlternativeName, true, true));
    GeneralNameType gn = new GeneralNameType();
    last(list).setSubjectAltName(gn);
    gn.addTags(GeneralNameTag.rfc822Name, GeneralNameTag.DNSName, GeneralNameTag.directoryName,
        GeneralNameTag.ediPartyName, GeneralNameTag.uniformResourceIdentifier,
        GeneralNameTag.IPAddress, GeneralNameTag.registeredID);
    gn.addOtherNames(createOidType(DN.O));

    // SubjectInfoAccess
    list.add(createExtension(Extension.subjectInfoAccess, true, false));
    SubjectInfoAccess subjectInfoAccess = new SubjectInfoAccess();
    last(list).setSubjectInfoAccess(subjectInfoAccess);
    SubjectInfoAccess.Access access = new SubjectInfoAccess.Access();
    subjectInfoAccess.getAccesses().add(access);

    access.setAccessMethod(createOidType(Extn.id_ad_caRepository));

    GeneralNameType accessLocation = new GeneralNameType();
    access.setAccessLocation(accessLocation);
    accessLocation.addTags(GeneralNameTag.directoryName,
        GeneralNameTag.uniformResourceIdentifier);

    marshall(profile, destFilename, true);
  } // method certprofileSubCaComplex

  private static void certprofileMultipleOus(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile multiple-ous", CertLevel.EndEntity, "5y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));

    rdnControls.add(createRdn(DN.OU, 2, 2));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.contentCommitment},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileMultipleOus

  /*
   * O and OU in one RDN
   */
  private static void certprofileMultipleValuedRdn(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile multiple-valued-rdn",
        CertLevel.EndEntity, "5y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1, null, null, null, "group1"));
    rdnControls.add(createRdn(DN.OU, 1, 1, null, null, null, "group1"));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.contentCommitment},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileMultipleValuedRdn

  private static void certprofileQc(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile qc", CertLevel.EndEntity, "1000d");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.organizationIdentifier, 0, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, false));
    last(list).setBasicConstrains(createBasicConstraints(1));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.contentCommitment},
        null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, true));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_timeStamping}, null));

    // privateKeyUsagePeriod
    list.add(createExtension(Extension.privateKeyUsagePeriod, true, false));
    last(list).setPrivateKeyUsagePeriod(createPrivateKeyUsagePeriod("3y"));

    // QcStatements
    list.add(createExtension(Extension.qCStatements, true, false));
    last(list).setQcStatements(createQcStatements(false));

    marshall(profile, destFilename, true);
  } // method certprofileQc

  private static void certprofileEeComplex(String destFilename)
      throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile ee-complex", CertLevel.EndEntity,
        "5y", true, false);

    // Subject
    Subject subject = profile.getSubject();
    subject.setKeepRdnOrder(false);
    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.CN, 1, 1));
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.dateOfBirth, 0, 1));
    rdnControls.add(createRdn(DN.postalAddress, 0, 1));
    rdnControls.add(createRdn(DN.userid, 1, 1));
    rdnControls.add(createRdn(DN.jurisdictionOfIncorporationCountryName, 1, 1));
    rdnControls.add(createRdn(DN.jurisdictionOfIncorporationLocalityName, 1, 1));
    rdnControls.add(createRdn(DN.jurisdictionOfIncorporationStateOrProvinceName, 1, 1));
    rdnControls.add(createRdn(Extn.id_extension_admission, 0, 99));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, false));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));
    last(list).setAuthorityKeyIdentifier(createAKIwithSerialAndSerial());

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment},
        null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth},
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}));

    // Extension - subjectDirectoryAttributes
    list.add(createExtension(Extension.subjectDirectoryAttributes, true, false));
    SubjectDirectoryAttributs subjectDirAttrType = new SubjectDirectoryAttributs();
    last(list).setSubjectDirectoryAttributs(subjectDirAttrType);

    List<DescribableOid> attrTypes = subjectDirAttrType.getTypes();
    attrTypes.add(createOidType(DN.countryOfCitizenship));
    attrTypes.add(createOidType(DN.countryOfResidence));
    attrTypes.add(createOidType(DN.gender));
    attrTypes.add(createOidType(DN.dateOfBirth));
    attrTypes.add(createOidType(DN.placeOfBirth));

    // Extensions - tlsFeature
    list.add(createExtension(Extn.id_pe_tlsfeature, true, true));
    last(list).setTlsFeature(createTlsFeature(
        TlsExtensionType.STATUS_REQUEST, TlsExtensionType.CLIENT_CERTIFICATE_URL));

    // Extension - Admission
    list.add(createExtension(Extn.id_extension_admission, true, false));
    AdmissionSyntax admissionSyntax = new AdmissionSyntax();
    last(list).setAdmissionSyntax(admissionSyntax);

    admissionSyntax.setAdmissionAuthority(
        new GeneralName(new X500Name("C=DE,CN=admissionAuthority level 1")).getEncoded());
    AdmissionsType admissions = new AdmissionsType();
    admissions.setAdmissionAuthority(
        new GeneralName(new X500Name("C=DE,CN=admissionAuthority level 2")).getEncoded());

    NamingAuthorityType namingAuthorityL2 = new NamingAuthorityType();
    namingAuthorityL2.setOid(createOidType(new ASN1ObjectIdentifier("1.2.3.4.5")));
    namingAuthorityL2.setUrl("http://naming-authority-level2.myorg.org");
    namingAuthorityL2.setText("namingAuthrityText level 2");
    admissions.setNamingAuthority(namingAuthorityL2);

    admissionSyntax.getContentsOfAdmissions().add(admissions);

    ProfessionInfoType pi = new ProfessionInfoType();
    admissions.getProfessionInfos().add(pi);

    pi.getProfessionOids().add(createOidType(new ASN1ObjectIdentifier("1.2.3.4"), "demo oid"));
    pi.getProfessionItems().add("demo item");

    NamingAuthorityType namingAuthorityL3 = new NamingAuthorityType();
    namingAuthorityL3.setOid(createOidType(new ASN1ObjectIdentifier("1.2.3.4.5")));
    namingAuthorityL3.setUrl("http://naming-authority-level3.myorg.org");
    namingAuthorityL3.setText("namingAuthrityText level 3");
    pi.setNamingAuthority(namingAuthorityL3);
    pi.setAddProfessionInfo(new byte[]{1, 2, 3, 4});

    RegistrationNumber regNum = new RegistrationNumber();
    pi.setRegistrationNumber(regNum);
    regNum.setRegex("a*b");

    // restriction
    list.add(createExtension(Extn.id_extension_restriction, true, false));
    last(list).setRestriction(
        createRestriction(DirectoryStringType.utf8String, "demo restriction"));

    // additionalInformation
    list.add(createExtension(
              Extn.id_extension_additionalInformation, true, false));
    last(list).setAdditionalInformation(createAdditionalInformation(DirectoryStringType.utf8String,
        "demo additional information"));

    // validationModel
    list.add(createExtension(Extn.id_extension_validityModel, true, false));
    last(list).setValidityModel(
        createValidityModel(
            createOidType(new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.5.1"), "chain")));

    // privateKeyUsagePeriod
    list.add(createExtension(Extension.privateKeyUsagePeriod, true, false));
    last(list).setPrivateKeyUsagePeriod(createPrivateKeyUsagePeriod("3y"));

    // QcStatements
    list.add(createExtension(Extension.qCStatements, true, false));
    last(list).setQcStatements(createQcStatements(true));

    // biometricInfo
    list.add(createExtension(Extension.biometricInfo, true, false));
    last(list).setBiometricInfo(createBiometricInfo());

    // SubjectAltName
    list.add(createExtension(Extension.subjectAlternativeName, true, true));
    GeneralNameType gn = new GeneralNameType();
    last(list).setSubjectAltName(gn);
    gn.addTags(GeneralNameTag.rfc822Name, GeneralNameTag.DNSName, GeneralNameTag.directoryName,
        GeneralNameTag.ediPartyName, GeneralNameTag.uniformResourceIdentifier,
        GeneralNameTag.IPAddress, GeneralNameTag.registeredID);
    gn.addOtherNames(
        createOidType(new ASN1ObjectIdentifier("1.2.3.1")),
        createOidType(new ASN1ObjectIdentifier("1.2.3.2")));

    // SubjectInfoAccess
    list.add(createExtension(Extension.subjectInfoAccess, true, false));
    SubjectInfoAccess subjectInfoAccess = new SubjectInfoAccess();
    last(list).setSubjectInfoAccess(subjectInfoAccess);

    List<ASN1ObjectIdentifier> accessMethods = new LinkedList<>();
    accessMethods.add(Extn.id_ad_caRepository);
    for (int i = 0; i < 10; i++) {
      accessMethods.add(new ASN1ObjectIdentifier("2.3.4." + (i + 1)));
    }

    for (ASN1ObjectIdentifier accessMethod : accessMethods) {
      SubjectInfoAccess.Access access = new SubjectInfoAccess.Access();
      subjectInfoAccess.getAccesses().add(access);
      access.setAccessMethod(createOidType(accessMethod));

      GeneralNameType accessLocation = new GeneralNameType();
      access.setAccessLocation(accessLocation);

      accessLocation.addTags(
          GeneralNameTag.rfc822Name, GeneralNameTag.DNSName, GeneralNameTag.directoryName,
          GeneralNameTag.ediPartyName, GeneralNameTag.uniformResourceIdentifier,
          GeneralNameTag.IPAddress, GeneralNameTag.registeredID);
      accessLocation.addOtherNames(
          createOidType(new ASN1ObjectIdentifier("1.2.3.1")),
          createOidType(new ASN1ObjectIdentifier("1.2.3.2")));
    }

    marshall(profile, destFilename, true);
  } // method certprofileEeComplex

  private static void certprofileConstantExtImplicitTag(String destFilename)
      throws Exception {
    certprofileConstantExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.2"), new Tag(1, false));
  }

  private static void certprofileConstantExtExplicitTag(String destFilename)
      throws Exception {
    certprofileConstantExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.3"), new Tag(1, true));
  }

  private static void certprofileConstantExt(String destFilename)
      throws Exception {
    certprofileConstantExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.1"), null);
  }

  private static void certprofileConstantExt(String destFilename, ASN1ObjectIdentifier oidPrefix,
      Tag tag)
          throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile constant-extension", CertLevel.EndEntity,
        "5y", true, false);

    // Subject
    Subject subject = profile.getSubject();
    subject.setKeepRdnOrder(true);
    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.CN, 1, 1));
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, false));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment},
        null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth},
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}));

    // Custom Constant Extension Value
    list.addAll(createConstantExtensions(oidPrefix, tag));

    marshall(profile, destFilename, true);
  } // method certprofileConstantExt

  private static void certprofileSyntaxExtImplicitTag(String destFilename) {
    certprofileSyntaxExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.2"), new Tag(1, false));
  }

  private static void certprofileSyntaxExtExplicitTag(String destFilename) {
    certprofileSyntaxExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.3"), new Tag(1, true));
  }

  private static void certprofileSyntaxExt(String destFilename) {
    certprofileSyntaxExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.1"), null);
  }

  private static void certprofileSyntaxExt(String destFilename,
      ASN1ObjectIdentifier oidPrefix, Tag tag) {
    X509ProfileType profile = getBaseProfile("certprofile syntax-extension", CertLevel.EndEntity,
        "5y", true, false);

    // Subject
    Subject subject = profile.getSubject();
    subject.setKeepRdnOrder(true);
    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.CN, 1, 1));
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, false));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment},
        null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth},
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}));

    // Custom extension with syntax
    list.addAll(createSyntaxExtensions(oidPrefix, tag));

    marshall(profile, destFilename, true);
  } // method certprofileSyntaxExt

  private static void certprofileFixedPartialSubject(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile fixed subject O and C",
        CertLevel.EndEntity, "365d", false);

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();

    ValueType value = new ValueType();
    value.setText("DE");
    value.setOverridable(true);
    rdnControls.add(createRdn(DN.C, null, null, value));

    value = new ValueType();
    value.setText("fixed myorg.org");
    value.setOverridable(false);
    rdnControls.add(createRdn(DN.O, null, null, value));

    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileFixedPartialSubject

  private static void certprofileAppleWwdr(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile apple WWDR",
        CertLevel.EndEntity, "395d");

    // Subject
    Subject subject = profile.getSubject();
    subject.setKeepRdnOrder(true);
    List<RdnType> rdnControls = subject.getRdns();

    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 1, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1));
    rdnControls.add(createRdn(DN.UID, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));
    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    list.add(createExtension(Extension.cRLDistributionPoints, true, false, null));

    // Extensions - CeritifcatePolicies
    // Certificate Policies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    CertificatePolicies extValue = new CertificatePolicies();
    last(list).setCertificatePolicies(extValue);

    List<CertificatePolicyInformationType> pis = extValue.getCertificatePolicyInformations();
    CertificatePolicyInformationType single = new CertificatePolicyInformationType();
    pis.add(single);
    single.setPolicyIdentifier(createOidType(
        new ASN1ObjectIdentifier("1.2.840.113635.100.5.1")));
    List<PolicyQualifier> qualifiers = new ArrayList<>(1);
    single.setPolicyQualifiers(qualifiers);

    PolicyQualifier qualifier = new PolicyQualifier();
    qualifiers.add(qualifier);
    qualifier.setType(PolicyQualfierType.userNotice);
    qualifier.setValue("Reliance on this certificate by any party assumes acceptance of the then "
        + "applicable standard terms and conditions of use, certificate policy and certification "
        + "practice statements.");

    qualifier = new PolicyQualifier();
    qualifiers.add(qualifier);
    qualifier.setType(PolicyQualfierType.cpsUri);
    qualifier.setValue("http://www.apple.com/certificateauthority");

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature},
        null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth},
        null));

    // apple custom extension 1.2.840.113635.100.6.3.1
    list.add(createConstantExtension(new ASN1ObjectIdentifier("1.2.840.113635.100.6.3.1"),
            true, false, null, FieldType.NULL, null));

    // apple custom extension 1.2.840.113635.100.6.3.2
    list.add(createConstantExtension(new ASN1ObjectIdentifier("1.2.840.113635.100.6.3.2"),
        true, false, null, FieldType.NULL, null));

    // apple custom extension 1.2.840.113635.100.6.3.6
    list.add(createExtension(new ASN1ObjectIdentifier("1.2.840.113635.100.6.3.6"), true, false));
    ExtnSyntax syntax = new ExtnSyntax(FieldType.SEQUENCE);
    last(list).setSyntax(syntax);
    last(list).setPermittedInRequest(true);

    /*
     *  1. SEQUENCE or SET {
     *  2.    UTF8String # abc.def.myBlog EXPLICIT
     *  3.    SEQUENCE
     *  4.      UTF8String  # app
     *  5.    UTF8String  # abc.def.myBlog.voip EXPLICIT
     *  6.    SEQUENCE EXPLICIT
     *  7.      UTF8String  # voip
     *  8.    UTF8String  # abc.def.myBlog.complication IMPLICIT
     *  9.    SEQUENCE IMPLICIT
     * 10.      UTF8String  # complication
     * 11. }
     */
    List<SubFieldSyntax> subFields = new LinkedList<>();
    // Line 2
    SubFieldSyntax subField = new SubFieldSyntax(FieldType.UTF8String);
    subFields.add(subField);
    subField.setRequired(true);

    // Line 3-4
    subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);
    subField.setRequired(true);

    SubFieldSyntax subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subsubField.setRequired(true);
    subField.setSubFields(Collections.singletonList(subsubField));

    // Line 5
    subField = new SubFieldSyntax(FieldType.UTF8String);
    subField.setRequired(true);
    subFields.add(subField);

    // Line 6-7
    subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);

    subField.setRequired(true);
    subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subsubField.setRequired(true);
    subField.setSubFields(Collections.singletonList(subsubField));

    // Line 8
    subField = new SubFieldSyntax(FieldType.UTF8String);
    subFields.add(subField);
    subField.setRequired(true);

    // Line 9-10
    subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);

    subField.setRequired(true);
    subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subsubField.setRequired(true);
    subField.setSubFields(Collections.singletonList(subsubField));

    syntax.setSubFields(subFields);

    marshall(profile, destFilename, true);
  } // method certprofileAppleWwdr

  private static void certprofileExtended(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile extended", CertLevel.EndEntity, "5y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1, ":FQDN", null, null));

    // SubjectToSubjectAltName
    List<SubjectToSubjectAltNameType> subjectToSubjectAltNames = new LinkedList<>();
    profile.setSubjectToSubjectAltNames(subjectToSubjectAltNames);

    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    subjectToSubjectAltNames.add(s2sType);
    s2sType.setSource(createOidType(DN.CN));
    s2sType.setTarget(GeneralNameTag.DNSName);

    // Extensions
    // Extensions - general

    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - SubjectAltNames
    list.add(createExtension(Extension.subjectAlternativeName, true, false));
    GeneralNameType gn = new GeneralNameType();
    last(list).setSubjectAltName(gn);
    gn.addTags(GeneralNameTag.DNSName, GeneralNameTag.IPAddress);

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment},
        null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth},
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}));

    // Extensions - tlsFeature
    list.add(createExtension(Extn.id_pe_tlsfeature, true, true));
    last(list).setTlsFeature(
        createTlsFeature(TlsExtensionType.STATUS_REQUEST,
                TlsExtensionType.CLIENT_CERTIFICATE_URL));

    // Extensions - SMIMECapabilities
    list.add(createExtension(Extn.id_smimeCapabilities, true, false));
    last(list).setSmimeCapabilities(createSmimeCapabilities());

    // Extensions - 1.2.3.4.1 (demo_without_conf)
    list.add(
        createExtension(new ASN1ObjectIdentifier("1.2.3.4.1"), true, false, "demo_without_conf"));

    // Extensions - 1.2.3.4.2 (demo_with_conf)
    list.add(
        createExtension(new ASN1ObjectIdentifier("1.2.3.4.2"), true, false, "demo_with_conf"));
    ExtnDemoWithConf demoWithConf = new ExtnDemoWithConf();
    demoWithConf.setTexts(Arrays.asList("text1", "text2"));
    last(list).setCustom(demoWithConf);

    // cannot validate due to some additional customized extensions.
    marshall(profile, destFilename, false);
  } // method certprofileExtended
}
