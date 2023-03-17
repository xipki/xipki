// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

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
import org.xipki.ca.certprofile.xijson.conf.Subject.RdnType;
import org.xipki.ca.certprofile.xijson.conf.Subject.ValueType;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.TlsExtensionType;

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
      certprofileExtended("certprofile-extended.json");
      certprofileConstantExt("certprofile-constant-ext.json");
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void certprofileSubCaComplex(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile subca-complex (with most extensions)",
        CertLevel.SubCA, "8y");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN),
      rdn(DN.CN, 1, 1, null, "PREFIX ", " SUFFIX"));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));
    last(list).setBasicConstraints(createBasicConstraints(1));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign}, null));

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
        createPolicyIdMapping(new ASN1ObjectIdentifier("1.1.1.1.1"), new ASN1ObjectIdentifier("2.1.1.1.1")));
    last(list).getPolicyMappings().getMappings().add(
        createPolicyIdMapping(new ASN1ObjectIdentifier("1.1.1.1.2"), new ASN1ObjectIdentifier("2.1.1.1.2")));

    // Policy Constraints
    list.add(createExtension(Extension.policyConstraints, true, true));
    last(list).setPolicyConstraints(createPolicyConstraints(2, 2));

    // Name Constraints
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
    accessLocation.addTags(GeneralNameTag.directoryName, GeneralNameTag.uniformResourceIdentifier);

    marshall(profile, destFilename, true);
  } // method certprofileSubCaComplex

  private static void certprofileMultipleOus(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile multiple-ous", CertLevel.EndEntity, "5y");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn(DN.OU, 2, 2), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.contentCommitment}, null));

    marshall(profile, destFilename, true);
  } // method certprofileMultipleOus

  /*
   * O and OU in one RDN
   */
  private static void certprofileMultipleValuedRdn(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile multiple-valued-rdn", CertLevel.EndEntity, "5y");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O, 1, 1, null, null, null, "group1"),
        rdn(DN.OU, 1, 1, null, null, null, "group1"), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.contentCommitment}, null));

    marshall(profile, destFilename, true);
  } // method certprofileMultipleValuedRdn

  private static void certprofileQc(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile qc", CertLevel.EndEntity, "1000d");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.organizationIdentifier), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, false));
    last(list).setBasicConstraints(createBasicConstraints(1));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.contentCommitment}, null));

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

  private static void certprofileEeComplex(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile ee-complex", CertLevel.EndEntity,
        "5y", true, false);

    // Subject
    addRdns(profile, rdn(DN.CN), rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN), rdn01(DN.dateOfBirth),
        rdn01(DN.postalAddress), rdn(DN.userid), rdn(DN.jurisdictionOfIncorporationCountryName),
        rdn(DN.jurisdictionOfIncorporationLocalityName), rdn(DN.jurisdictionOfIncorporationStateOrProvinceName),
        rdn(Extn.id_extension_admission, 0, 99));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment, KeyUsage.keyEncipherment}, null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth},
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}));

    // Extensions - tlsFeature
    list.add(createExtension(Extn.id_pe_tlsfeature, true, true));
    last(list).setTlsFeature(
        createTlsFeature(TlsExtensionType.STATUS_REQUEST, TlsExtensionType.CLIENT_CERTIFICATE_URL));

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
    last(list).setRestriction(createRestriction(DirectoryStringType.utf8String, "demo restriction"));

    // additionalInformation
    list.add(createExtension(Extn.id_extension_additionalInformation, true, false));
    last(list).setAdditionalInformation(createAdditionalInformation(DirectoryStringType.utf8String,
        "demo additional information"));

    // validationModel
    list.add(createExtension(Extn.id_extension_validityModel, true, false));
    last(list).setValidityModel(
        createValidityModel(createOidType(new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.5.1"), "chain")));

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
    gn.addOtherNames(createOidType(new ASN1ObjectIdentifier("1.2.3.1")),
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
          GeneralNameTag.rfc822Name, GeneralNameTag.DNSName, GeneralNameTag.directoryName, GeneralNameTag.ediPartyName,
          GeneralNameTag.uniformResourceIdentifier, GeneralNameTag.IPAddress, GeneralNameTag.registeredID);
      accessLocation.addOtherNames(createOidType(new ASN1ObjectIdentifier("1.2.3.1")),
          createOidType(new ASN1ObjectIdentifier("1.2.3.2")));
    }

    marshall(profile, destFilename, true);
  } // method certprofileEeComplex

  private static void certprofileConstantExt(String destFilename) throws Exception {
    certprofileConstantExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.1"));
  }

  private static void certprofileConstantExt(String destFilename, ASN1ObjectIdentifier oidPrefix)
      throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile constant-extension", CertLevel.EndEntity,
        "5y", true, false);

    // Subject
    profile.getSubject().setKeepRdnOrder(true);
    addRdns(profile, rdn(DN.CN), rdn(DN.C), rdn(DN.O), rdn01(DN.OU));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment, KeyUsage.keyEncipherment}, null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth},
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}));

    // Custom Constant Extension Value
    list.addAll(createConstantExtensions(oidPrefix));

    marshall(profile, destFilename, true);
  } // method certprofileConstantExt

  private static void certprofileFixedPartialSubject(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile fixed subject O and C",
        CertLevel.EndEntity, "365d", false);

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();

    ValueType value = new ValueType();
    value.setText("DE");
    value.setOverridable(true);
    rdnControls.add(rdn(DN.C, null, null, value));

    value = new ValueType();
    value.setText("fixed myorg.org");
    value.setOverridable(false);
    rdnControls.add(rdn(DN.O, null, null, value));

    rdnControls.add(rdn(DN.OU, 0, 1));
    rdnControls.add(rdn(DN.SN, 0, 1));
    rdnControls.add(rdn(DN.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment, KeyUsage.keyEncipherment}, null));

    marshall(profile, destFilename, true);
  } // method certprofileFixedPartialSubject

  private static void certprofileExtended(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile extended", CertLevel.EndEntity, "5y");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN),
        rdn(DN.CN, 1, 1, ":FQDN", null, null));

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
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment, KeyUsage.keyEncipherment}, null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth},
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}));

    // Extensions - tlsFeature
    list.add(createExtension(Extn.id_pe_tlsfeature, true, true));
    last(list).setTlsFeature(createTlsFeature(
        TlsExtensionType.STATUS_REQUEST, TlsExtensionType.CLIENT_CERTIFICATE_URL));

    // Extensions - SMIMECapabilities
    list.add(createExtension(Extn.id_smimeCapabilities, true, false));
    last(list).setSmimeCapabilities(createSmimeCapabilities());

    // Extensions - 1.2.3.4.1 (demo_without_conf)
    list.add(createExtension(new ASN1ObjectIdentifier("1.2.3.4.1"), true, false, "demo_without_conf"));

    // Extensions - 1.2.3.4.2 (demo_with_conf)
    list.add(createExtension(new ASN1ObjectIdentifier("1.2.3.4.2"), true, false, "demo_with_conf"));
    ExtnDemoWithConf demoWithConf = new ExtnDemoWithConf();
    demoWithConf.setTexts(Arrays.asList("text1", "text2"));
    last(list).setCustom(demoWithConf);

    // cannot validate due to some additional customized extensions.
    marshall(profile, destFilename, false);
  } // method certprofileExtended
}
