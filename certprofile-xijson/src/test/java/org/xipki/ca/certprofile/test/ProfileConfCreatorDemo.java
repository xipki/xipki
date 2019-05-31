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

package org.xipki.ca.certprofile.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.ca.api.profile.Certprofile.CertDomain;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.api.profile.Certprofile.X509CertVersion;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.certprofile.xijson.DirectoryStringType;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.AlgorithmType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicyInformationType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicyInformationType.PolicyQualfierType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicyInformationType.PolicyQualifier;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableBinary;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AdditionalInformation;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AdmissionSyntax;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AdmissionsType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AuthorityInfoAccess;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AuthorityKeyIdentifier;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AuthorizationTemplate;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.BasicConstraints;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.BiometricInfo;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.BiometricTypeType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.CertificatePolicies;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.CrlDistributionPoints;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ExtendedKeyUsage;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ExtnSyntax;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ExtnSyntax.SubFieldSyntax;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.NameConstraints;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.NamingAuthorityType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.PolicyIdMappingType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.PolicyMappings;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.PrivateKeyUsagePeriod;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ProfessionInfoType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.QcStatements;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.RegistrationNumber;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.Restriction;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SmimeCapabilities;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SmimeCapability;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SmimeCapabilityParameter;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SubjectDirectoryAttributs;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SubjectInfoAccess;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.TlsFeature;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ValidityModel;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.ca.certprofile.xijson.conf.KeyParametersType;
import org.xipki.ca.certprofile.xijson.conf.KeyParametersType.DsaParametersType;
import org.xipki.ca.certprofile.xijson.conf.KeyParametersType.EcParametersType;
import org.xipki.ca.certprofile.xijson.conf.KeyParametersType.RsaParametersType;
import org.xipki.ca.certprofile.xijson.conf.KeypairGenerationType;
import org.xipki.ca.certprofile.xijson.conf.KeypairGenerationType.KeyType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.PdsLocationType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.QcEuLimitValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.QcStatementValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.Range2Type;
import org.xipki.ca.certprofile.xijson.conf.Subject;
import org.xipki.ca.certprofile.xijson.conf.Subject.RdnType;
import org.xipki.ca.certprofile.xijson.conf.Subject.ValueType;
import org.xipki.ca.certprofile.xijson.conf.SubjectToSubjectAltNameType;
import org.xipki.ca.certprofile.xijson.conf.X509ProfileType;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.BaseRequirements;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.TlsExtensionType;
import org.xipki.security.X509ExtensionType.ConstantExtnValue;
import org.xipki.security.X509ExtensionType.FieldType;
import org.xipki.security.X509ExtensionType.Tag;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.TripleState;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

/**
 * Demo the creation of xijson configuration.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ProfileConfCreatorDemo {

  public static class ExtnDemoWithConf {
    private List<String> texts;

    public List<String> getTexts() {
      return texts;
    }

    public void setTexts(List<String> texts) {
      this.texts = texts;
    }

  }

  private static final String REGEX_SN = ":NUMBER";

  private static final String REGEX_FQDN = ":FQDN";

  private static final Set<ASN1ObjectIdentifier> REQUEST_EXTENSIONS;

  private static final Set<ASN1ObjectIdentifier> NOT_IN_SUBJECT_RDNS;

  static {
    REQUEST_EXTENSIONS = new HashSet<>();
    REQUEST_EXTENSIONS.add(Extension.keyUsage);
    REQUEST_EXTENSIONS.add(Extension.extendedKeyUsage);
    REQUEST_EXTENSIONS.add(Extension.subjectAlternativeName);
    REQUEST_EXTENSIONS.add(Extension.subjectDirectoryAttributes);
    REQUEST_EXTENSIONS.add(Extension.subjectInfoAccess);
    REQUEST_EXTENSIONS.add(Extension.qCStatements);
    REQUEST_EXTENSIONS.add(Extension.biometricInfo);
    REQUEST_EXTENSIONS.add(Extn.id_extension_admission);
    REQUEST_EXTENSIONS.add(Extn.id_extension_additionalInformation);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_ICRegistrationNumber);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_IdentityCode);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_InsuranceNumber);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_OrganizationCode);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_TaxationNumber);

    NOT_IN_SUBJECT_RDNS = new HashSet<>();
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_ICRegistrationNumber);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_IdentityCode);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_InsuranceNumber);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_OrganizationCode);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_TaxationNumber);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_extension_admission);
  }

  private ProfileConfCreatorDemo() {
  }

  public static void main(String[] args) {
    try {
      // CA/Browser Forum
      certprofileCabRootCa("certprofile-cab-rootca.json");
      certprofileCabSubCa("certprofile-cab-subca.json");
      certprofileCabDomainValidatedTls("certprofile-cab-domain-validated.json");
      certprofileCabOrganizationValidatedTls("certprofile-cab-org-validated.json");
      certprofileCabIndividualValidatedTls("certprofile-cab-individual-validated.json");

      certprofileRootCa("certprofile-rootca.json");
      certprofileCross("certprofile-cross.json");
      certprofileSubCa("certprofile-subca.json");
      certprofileSubCaComplex("certprofile-subca-complex.json");
      certprofileOcsp("certprofile-ocsp.json");
      certprofileScep("certprofile-scep.json");
      certprofileEeComplex("certprofile-ee-complex.json");
      certprofileQc("certprofile-qc.json");
      certprofileSmime("certprofile-smime.json", false);
      certprofileSmime("certprofile-smime-legacy.json", true);
      certprofileTls("certprofile-tls.json", false);
      certprofileTls("certprofile-tls-inc-sn.json", true);
      certprofileTlsC("certprofile-tls-c.json");
      certprofileMultipleOus("certprofile-multiple-ous.json");
      certprofileMultipleValuedRdn("certprofile-multi-valued-rdn.json");
      certprofileMaxTime("certprofile-max-time.json");
      certprofileFixedPartialSubject("certprofile-fixed-partial-subject.json");
      certprofileConstantExt("certprofile-constant-ext.json");
      certprofileConstantExtImplicitTag("certprofile-constant-ext-implicit-tag.json");
      certprofileConstantExtExplicitTag("certprofile-constant-ext-explicit-tag.json");
      certprofileSyntaxExt("certprofile-syntax-ext.json");
      certprofileSyntaxExtImplicitTag("certprofile-syntax-ext-implicit-tag.json");
      certprofileSyntaxExtExplicitTag("certprofile-syntax-ext-explicit-tag.json");
      certprofileExtended("certprofile-extended.json");
      certprofileAppleWwdr("certprofile-apple-wwdr.json");
      certprofileGmt0015("certprofile-gmt0015.json");

      certprofileTlsEdwardsOrMontgomery("certprofile-ed25519.json", true,  true);
      certprofileTlsEdwardsOrMontgomery("certprofile-ed448.json",   true,  false);
      certprofileTlsEdwardsOrMontgomery("certprofile-x25519.json",  false, true);
      certprofileTlsEdwardsOrMontgomery("certprofile-x448.json",    false, false);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void marshall(X509ProfileType profile, String filename, boolean validate) {
    try {
      Path path = Paths.get("tmp", filename);
      IoUtil.mkdirsParent(path);
      try (OutputStream out = Files.newOutputStream(path)) {
        JSON.writeJSONString(out, profile,
            SerializerFeature.PrettyFormat, SerializerFeature.SortField,
            SerializerFeature.DisableCircularReferenceDetect);
      }

      if (validate) {
        X509ProfileType profileConf;
        // Test by deserializing
        try (InputStream is = Files.newInputStream(path)) {
          profileConf = X509ProfileType.parse(is);
        }
        XijsonCertprofile profileObj = new XijsonCertprofile();
        profileObj.initialize(profileConf);
        profileObj.close();
        System.out.println("Generated certprofile in " + filename);
      }
    } catch (Exception ex) {
      System.err.println("Error while generating certprofile in " + filename);
      ex.printStackTrace();
    }

  } // method marshal

  private static void certprofileCabRootCa(String destFilename) throws Exception {
    X509ProfileType profile = getBaseCabProfile("certprofile RootCA (CA/Browser Forum BR)",
        CertLevel.RootCA, "10y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileCabRootCa

  private static void certprofileCabSubCa(String destFilename) throws Exception {
    X509ProfileType profile = getBaseCabProfile("certprofile SubCA (CA/Browser Forum BR)",
        CertLevel.SubCA, "8y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    last(list).setCrlDistributionPoints(createCrlDistibutoionPoints());

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

    // Extensions - CertificatePolicies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    Map<ASN1ObjectIdentifier, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(new ASN1ObjectIdentifier("1.2.3.4"), "http://abc.def.de/cfp");
    last(list).setCertificatePolicies(createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabSubCa

  private static void certprofileCabDomainValidatedTls(String destFilename) throws Exception {
    X509ProfileType profile = getBaseCabSubscriberProfile(
        "certprofile TLS (CA/Browser Forum BR, Domain Validated)");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    List<ExtensionType> list = profile.getExtensions();
    // Extensions - CertificatePolicies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    Map<ASN1ObjectIdentifier, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(BaseRequirements.id_domain_validated, null);
    last(list).setCertificatePolicies(createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabDomainValidatedTls

  private static void certprofileCabOrganizationValidatedTls(String destFilename) throws Exception {
    X509ProfileType profile = getBaseCabSubscriberProfile(
        "certprofile TLS (CA/Browser Forum BR, Organization Validiated)");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.ST, 0, 1));
    rdnControls.add(createRdn(DN.localityName, 0, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    List<ExtensionType> list = profile.getExtensions();
    // Extensions - CertificatePolicies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    Map<ASN1ObjectIdentifier, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(BaseRequirements.id_organization_validated, null);
    last(list).setCertificatePolicies(createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabOrganizationValidatedTls

  private static void certprofileCabIndividualValidatedTls(String destFilename) throws Exception {
    X509ProfileType profile = getBaseCabSubscriberProfile(
        "certprofile TLS (CA/Browser Forum BR, Individual Validiated)");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.ST, 0, 1));
    rdnControls.add(createRdn(DN.localityName, 0, 1));
    rdnControls.add(createRdn(DN.givenName, 1, 1));
    rdnControls.add(createRdn(DN.surname, 1, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    List<ExtensionType> list = profile.getExtensions();
    // Extensions - CertificatePolicies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    Map<ASN1ObjectIdentifier, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(BaseRequirements.id_individual_validated, null);
    last(list).setCertificatePolicies(createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabOrganizationValidatedTls

  private static X509ProfileType getBaseCabSubscriberProfile(String desc) throws Exception {
    X509ProfileType profile = getBaseCabProfile(desc, CertLevel.EndEntity, "2y");

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(DN.CN));
    s2sType.setTarget(GeneralNameTag.DNSName);

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    last(list).setCrlDistributionPoints(createCrlDistibutoionPoints());

    // Extensions - SubjectAltNames
    list.add(createExtension(Extension.subjectAlternativeName, true, false));
    GeneralNameType san = new GeneralNameType();
    last(list).setSubjectAltName(san);
    san.addTags(GeneralNameTag.DNSName, GeneralNameTag.IPAddress);

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

    // Extensions - CTLog
    list.add(createExtension(Extn.id_SCTs, true, false));

    return profile;
  } // method certprofileCabTls

  private static void certprofileRootCa(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile rootca", CertLevel.RootCA, "10y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileRootCa

  private static void certprofileCross(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile cross", CertLevel.SubCA, "10y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1));

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
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign}, null));

    marshall(profile, destFilename, true);
  } // method certprofileCross

  private static void certprofileSubCa(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile subca", CertLevel.SubCA, "8y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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

    marshall(profile, destFilename, true);
  } // method certprofileSubCa

  private static void certprofileSubCaComplex(String destFilename) throws Exception {
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
    policies.put(new ASN1ObjectIdentifier("1.2.3.4.5"), "http://example.org/ca1-cps");
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

  private static List<ConstantExtnValue> createConstantSequenceOrSet() {
    /*
     *  1. SEQUENCE or SET {
     *  2.       UTF8String abc.def.myBlog EXPLICIT
     *  3.       SEQUENCE
     *  4.         UTF8String app
     *  5.   [0] UTF8String abc.def.myBlog.voip EXPLICIT
     *  6.   [1] SEQUENCE EXPLICIT
     *  7.         UTF8String voip
     *  8.   [2] UTF8String abc.def.myBlog.complication IMPLICIT
     *  9.   [3] SEQUENCE IMPLICIT
     * 10.         UTF8String complication
     * 11. }
     */
    List<ConstantExtnValue> subFields = new LinkedList<>();
    // Line 2
    ConstantExtnValue subField = new ConstantExtnValue(FieldType.UTF8String);
    subFields.add(subField);
    subField.setValue("abc.def.myBlog");

    // Line 3-4
    subField = new ConstantExtnValue(FieldType.SEQUENCE);
    subFields.add(subField);
    ConstantExtnValue subsubField = new ConstantExtnValue(FieldType.UTF8String);
    subsubField.setValue("app");
    subField.setListValue(Arrays.asList(subsubField));

    // Line 5
    subField = new ConstantExtnValue(FieldType.UTF8String);
    subFields.add(subField);
    subField.setTag(new Tag(0, true));
    subField.setValue("abc.def.myBlog.voip");

    // Line 6-7
    subField = new ConstantExtnValue(FieldType.SEQUENCE);
    subFields.add(subField);
    subField.setTag(new Tag(1, true));
    subsubField = new ConstantExtnValue(FieldType.UTF8String);
    subsubField.setValue("void");
    subField.setListValue(Arrays.asList(subsubField));

    // Line 8
    subField = new ConstantExtnValue(FieldType.UTF8String);
    subFields.add(subField);
    subField.setTag(new Tag(2, false));
    subField.setValue("abc.def.myBlog.complication");

    // Line 9-10
    subField = new ConstantExtnValue(FieldType.SEQUENCE);
    subFields.add(subField);
    subField.setTag(new Tag(9, false));
    subsubField = new ConstantExtnValue(FieldType.UTF8String);
    subsubField.setValue("complication");
    subField.setListValue(Arrays.asList(subsubField));

    return subFields;
  }

  private static List<SubFieldSyntax> createSyntaxSequenceOrSet() {
    /*
     *  1. SEQUENCE or SET {
     *  2.       UTF8String # abc.def.myBlog EXPLICIT
     *  3.       SEQUENCE
     *  4.         UTF8String  # app
     *  5.   [0] UTF8String  # abc.def.myBlog.voip EXPLICIT
     *  6.   [1] SEQUENCE EXPLICIT
     *  7.         UTF8String  # voip
     *  8.   [2] UTF8String  # abc.def.myBlog.complication IMPLICIT
     *  9.   [3] SEQUENCE IMPLICIT
     * 10.         UTF8String  # complication
     * 11. }
     */
    List<SubFieldSyntax> subFields = new LinkedList<>();
    // Line 2
    SubFieldSyntax subField = new SubFieldSyntax(FieldType.UTF8String);
    subFields.add(subField);

    // Line 3-4
    subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);
    SubFieldSyntax subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subField.setSubFields(Arrays.asList(subsubField));

    // Line 5
    subField = new SubFieldSyntax(FieldType.UTF8String);
    subFields.add(subField);
    subField.setTag(new Tag(0, true));

    // Line 6-7
    subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);
    subField.setTag(new Tag(1, true));
    subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subField.setSubFields(Arrays.asList(subsubField));

    // Line 8
    subField = new SubFieldSyntax(FieldType.UTF8String);
    subFields.add(subField);
    subField.setTag(new Tag(2, false));

    // Line 9-10
    subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);
    subField.setTag(new Tag(9, false));
    subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subField.setSubFields(Arrays.asList(subsubField));

    return subFields;
  }

  private static List<ConstantExtnValue> createConstantSequenceOfOrSetOf() {
    /*
     *  1. SEQUENCE or SET {
     *  3.   SEQUENCE
     *  3.     UTF8String abc.def.myBlog
     *  4.     UTF8String app
     *  5.   SEQUENCE
     *  6.       UTF8String abc.def.myBlog.voip
     *  7.       UTF8String voip
     *  8.   SEQUENCE
     *  9.     UTF8String abc.def.myBlog.complication
     * 10.     UTF8String complication
     * 11. }
     */
    List<ConstantExtnValue> subFields = new LinkedList<>();

    // Line 2-4
    {
      ConstantExtnValue subField = new ConstantExtnValue(FieldType.SEQUENCE);
      subFields.add(subField);

      List<ConstantExtnValue> subsubFields = new LinkedList<>();
      subField.setListValue(subsubFields);

      ConstantExtnValue subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("abc.def.myBlog");
      subsubFields.add(subsubField);

      subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("app");
      subsubFields.add(subsubField);
    }

    // Line 5-7
    {
      ConstantExtnValue subField = new ConstantExtnValue(FieldType.SEQUENCE);
      subFields.add(subField);

      List<ConstantExtnValue> subsubFields = new LinkedList<>();
      subField.setListValue(subsubFields);

      ConstantExtnValue subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("abc.def.myBlog.voip");
      subsubFields.add(subsubField);

      subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("voip");
      subsubFields.add(subsubField);
    }

    // Line 5-7
    {
      ConstantExtnValue subField = new ConstantExtnValue(FieldType.SEQUENCE);
      subFields.add(subField);

      List<ConstantExtnValue> subsubFields = new LinkedList<>();
      subField.setListValue(subsubFields);

      ConstantExtnValue subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("abc.def.myBlog.complication");
      subsubFields.add(subsubField);

      subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("complication");
      subsubFields.add(subsubField);
    }

    return subFields;
  }

  private static List<SubFieldSyntax> createSyntaxSequenceOfOrSetOf() {
    /*
     *  1. SEQUENCE OF or SET OF{
     *  3.   SEQUENCE
     *  3.     UTF8String
     *  4.     UTF8String
     *  5. }
     */
    List<SubFieldSyntax> subFields = new LinkedList<SubFieldSyntax>();

    // Line 2-4
    SubFieldSyntax subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);

    List<SubFieldSyntax> subsubFields = new LinkedList<>();
    subField.setSubFields(subsubFields);

    SubFieldSyntax subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subsubFields.add(subsubField);

    subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subsubFields.add(subsubField);

    return subFields;
  }

  private static void certprofileOcsp(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile ocsp", CertLevel.EndEntity, "5y",
        false, true);

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
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));
    list.add(createExtension(
              Extn.id_extension_pkix_ocsp_nocheck, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.contentCommitment},
        null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_ocspSigning}, null));

    marshall(profile, destFilename, true);
  } // method certprofileOcsp

  private static void certprofileScep(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile scep", CertLevel.EndEntity, "5y");

    profile.setKeyAlgorithms(createRSAKeyAlgorithms());

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.keyEncipherment}, null));

    marshall(profile, destFilename, true);
  } // method certprofileScep

  private static void certprofileSmime(String destFilename, boolean legacy) throws Exception {
    String desc = legacy ? "certprofile s/mime legacy" : "certprofile s/mime";
    X509ProfileType profile = getBaseProfile(desc, CertLevel.EndEntity, "5y", true, false);

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    if (legacy) {
      rdnControls.add(createRdn(DN.emailAddress, 1, 1));
    }
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(DN.emailAddress));
    s2sType.setTarget(GeneralNameTag.rfc822Name);

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - SubjectAltNames
    list.add(createExtension(Extension.subjectAlternativeName, true, false));
    GeneralNameType san = new GeneralNameType();
    last(list).setSubjectAltName(san);
    san.addTags(GeneralNameTag.rfc822Name);

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
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_emailProtection},
        null));

    // Extensions - SMIMECapabilities
    list.add(createExtension(Extn.id_smimeCapabilities, true, false));
    last(list).setSmimeCapabilities(createSmimeCapabilities());

    marshall(profile, destFilename, true);
  } // method certprofileTls

  private static void certprofileTlsEdwardsOrMontgomery(String destFilename, boolean edwards,
      boolean curve25519) throws Exception {
    String desc = "certprofile tls with "
                    + (edwards ? "edwards " : "montmomery ")
                    + (curve25519 ? "25519" : "448")
                    + " curves";

    X509ProfileType profile = getEeBaseProfileForEdwardsOrMontgomeryCurves(
        desc, "2y", edwards, curve25519);

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 0, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(DN.CN));
    s2sType.setTarget(GeneralNameTag.DNSName);

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - SubjectAltNames
    list.add(createExtension(Extension.subjectAlternativeName, true, false));
    GeneralNameType san = new GeneralNameType();
    last(list).setSubjectAltName(san);
    san.addTags(GeneralNameTag.DNSName, GeneralNameTag.IPAddress);

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth,
            ObjectIdentifiers.XKU.id_kp_clientAuth},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileTls

  private static void certprofileTls(String destFilename, boolean incSerial) throws Exception {
    String desc = incSerial ? "certprofile tls-inc-sn (serial number will be added automatically)"
        : "certprofile tls";
    X509ProfileType profile = getBaseProfile(desc, CertLevel.EndEntity, "5y", true, incSerial);

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(DN.CN));
    s2sType.setTarget(GeneralNameTag.DNSName);

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));

    // Extensions - SubjectAltNames
    list.add(createExtension(Extension.subjectAlternativeName, true, false));
    GeneralNameType san = new GeneralNameType();
    last(list).setSubjectAltName(san);
    san.addTags(GeneralNameTag.DNSName, GeneralNameTag.IPAddress);

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

    marshall(profile, destFilename, true);
  } // method certprofileTls

  private static void certprofileTlsC(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile tls-c", CertLevel.EndEntity, "5y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
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

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileTlsC

  private static void certprofileMultipleOus(String destFilename) throws Exception {
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
  private static void certprofileMultipleValuedRdn(String destFilename) throws Exception {
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

  private static void certprofileQc(String destFilename) throws Exception {
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
  } // method certprofileEeComplex

  private static void certprofileEeComplex(String destFilename) throws Exception {
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
    namingAuthorityL2.setUrl("http://naming-authority-level2.example.org");
    namingAuthorityL2.setText("namingAuthrityText level 2");
    admissions.setNamingAuthority(namingAuthorityL2);

    admissionSyntax.getContentsOfAdmissions().add(admissions);

    ProfessionInfoType pi = new ProfessionInfoType();
    admissions.getProfessionInfos().add(pi);

    pi.getProfessionOids().add(createOidType(new ASN1ObjectIdentifier("1.2.3.4"), "demo oid"));
    pi.getProfessionItems().add("demo item");

    NamingAuthorityType namingAuthorityL3 = new NamingAuthorityType();
    namingAuthorityL3.setOid(createOidType(new ASN1ObjectIdentifier("1.2.3.4.5")));
    namingAuthorityL3.setUrl("http://naming-authority-level3.example.org");
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

    // authorizationTemplate
    list.add(createExtension(
              ObjectIdentifiers.Xipki.id_xipki_ext_authorizationTemplate, true, false));
    last(list).setAuthorizationTemplate(createAuthorizationTemplate());

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

  private static void certprofileConstantExtImplicitTag(String destFilename) throws Exception {
    certprofileConstantExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.2"), new Tag(1, false));
  }

  private static void certprofileConstantExtExplicitTag(String destFilename) throws Exception {
    certprofileConstantExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.3"), new Tag(1, true));
  }

  private static void certprofileConstantExt(String destFilename) throws Exception {
    certprofileConstantExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.1"), null);
  }

  private static void certprofileConstantExt(String destFilename, ASN1ObjectIdentifier oidPrefix,
      Tag tag) throws Exception {
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

  private static void certprofileSyntaxExtImplicitTag(String destFilename) throws Exception {
    certprofileSyntaxExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.2"), new Tag(1, false));
  }

  private static void certprofileSyntaxExtExplicitTag(String destFilename) throws Exception {
    certprofileSyntaxExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.3"), new Tag(1, true));
  }

  private static void certprofileSyntaxExt(String destFilename) throws Exception {
    certprofileSyntaxExt(destFilename, new ASN1ObjectIdentifier("1.2.3.6.1"), null);
  }

  private static void certprofileSyntaxExt(String destFilename,
      ASN1ObjectIdentifier oidPrefix, Tag tag) throws Exception {
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

  private static List<ExtensionType> createConstantExtensions(
      ASN1ObjectIdentifier oidPrefix, Tag tag) throws IOException {
    List<ExtensionType> list = new LinkedList<>();

    // Custom Constant Extension Value
    list.add(createConstantExtension(oidPrefix.branch("1"), true, false, tag,
        FieldType.BIT_STRING, Base64.encodeToString(new byte[] {1, 2})));
    list.add(createConstantExtension(oidPrefix.branch("2"), true, false, tag,
        FieldType.BMPString, "A BMP string"));
    list.add(createConstantExtension(oidPrefix.branch("3"), true, false, tag,
        FieldType.BOOLEAN, Boolean.TRUE.toString()));
    list.add(createConstantExtension(oidPrefix.branch("4"), true, false, tag,
        FieldType.IA5String, "An IA5 string"));
    list.add(createConstantExtension(oidPrefix.branch("5"), true, false, tag,
        FieldType.INTEGER, "10"));
    list.add(createConstantExtension(oidPrefix.branch("6"), true, false, tag,
        FieldType.NULL, null));
    list.add(createConstantExtension(oidPrefix.branch("7"), true, false, tag,
        FieldType.OCTET_STRING, Base64.encodeToString(new byte[] {3, 4})));
    list.add(createConstantExtension(oidPrefix.branch("8"), true, false, tag,
        FieldType.OID, "2.3.4.5"));
    list.add(createConstantExtension(oidPrefix.branch("9"), true, false, tag,
        FieldType.PrintableString, "A printable string"));
    list.add(createConstantExtension(oidPrefix.branch("10"), true, false, tag,
        FieldType.RAW, Base64.encodeToString(DERNull.INSTANCE.getEncoded())));
    last(list).getConstant().setDescription("DER NULL");

    list.add(createConstantExtension(oidPrefix.branch("11"), true, false, tag,
        FieldType.TeletexString, "A teletax string"));
    list.add(createConstantExtension(oidPrefix.branch("12"), true, false, tag,
        FieldType.UTF8String, "A UTF8 string"));
    list.add(createConstantExtension(oidPrefix.branch("13"), true, false, tag,
        FieldType.ENUMERATED, "2"));
    list.add(createConstantExtension(oidPrefix.branch("14"), true, false, tag,
        FieldType.GeneralizedTime, new ASN1GeneralizedTime("20180314130102Z").getTimeString()));
    list.add(createConstantExtension(oidPrefix.branch("15"), true, false, tag,
        FieldType.UTCTime, "190314130102Z"));
    list.add(createConstantExtension(oidPrefix.branch("16"), true, false, tag,
        FieldType.Name, "CN=abc,C=DE"));

    list.add(createConstantExtension(oidPrefix.branch("17"), true, false, tag,
        FieldType.SEQUENCE, null));
    last(list).getConstant().setListValue(createConstantSequenceOrSet());

    list.add(createConstantExtension(oidPrefix.branch("18"), true, false, tag,
        FieldType.SEQUENCE_OF, null));
    last(list).getConstant().setListValue(createConstantSequenceOfOrSetOf());

    list.add(createConstantExtension(oidPrefix.branch("19"), true, false, tag,
        FieldType.SET, null));
    last(list).getConstant().setListValue(createConstantSequenceOrSet());

    list.add(createConstantExtension(oidPrefix.branch("20"), true, false, tag,
        FieldType.SET_OF, null));
    last(list).getConstant().setListValue(createConstantSequenceOfOrSetOf());

    return list;
  }

  private static List<ExtensionType> createSyntaxExtensions(ASN1ObjectIdentifier oidPrefix,
      Tag tag) {
    List<ExtensionType> list = new LinkedList<>();
    // Custom extension with syntax
    list.add(createSyntaxExtension(oidPrefix.branch("1"), true, false, tag,
        FieldType.BIT_STRING));
    list.add(createSyntaxExtension(oidPrefix.branch("2"), true, false, tag,
        FieldType.BMPString));
    list.add(createSyntaxExtension(oidPrefix.branch("3"), true, false, tag,
        FieldType.BOOLEAN));
    list.add(createSyntaxExtension(oidPrefix.branch("4"), true, false, tag,
        FieldType.IA5String));
    list.add(createSyntaxExtension(oidPrefix.branch("5"), true, false, tag,
        FieldType.INTEGER));
    list.add(createSyntaxExtension(oidPrefix.branch("6"), true, false, tag,
        FieldType.NULL));
    list.add(createSyntaxExtension(oidPrefix.branch("7"), true, false, tag,
        FieldType.OCTET_STRING));
    list.add(createSyntaxExtension(oidPrefix.branch("8"), true, false, tag,
        FieldType.OID));
    list.add(createSyntaxExtension(oidPrefix.branch("9"), true, false, tag,
        FieldType.PrintableString));
    list.add(createSyntaxExtension(oidPrefix.branch("10"), true, false, tag,
        FieldType.RAW));
    list.add(createSyntaxExtension(oidPrefix.branch("11"), true, false, tag,
        FieldType.TeletexString));
    list.add(createSyntaxExtension(oidPrefix.branch("12"), true, false, tag,
        FieldType.UTF8String));
    list.add(createSyntaxExtension(oidPrefix.branch("13"), true, false, tag,
        FieldType.ENUMERATED));
    list.add(createSyntaxExtension(oidPrefix.branch("14"), true, false, tag,
        FieldType.GeneralizedTime));
    list.add(createSyntaxExtension(oidPrefix.branch("15"), true, false, tag,
        FieldType.UTCTime));
    list.add(createSyntaxExtension(oidPrefix.branch("16"), true, false, tag,
        FieldType.Name));

    list.add(createSyntaxExtension(oidPrefix.branch("17"), true, false, tag,
        FieldType.SEQUENCE));
    last(list).getSyntax().setSubFields(createSyntaxSequenceOrSet());

    list.add(createSyntaxExtension(oidPrefix.branch("18"), true, false, tag,
        FieldType.SEQUENCE_OF));
    last(list).getSyntax().setSubFields(createSyntaxSequenceOfOrSetOf());

    list.add(createSyntaxExtension(oidPrefix.branch("19"), true, false, tag,
        FieldType.SET));
    last(list).getSyntax().setSubFields(createSyntaxSequenceOrSet());

    list.add(createSyntaxExtension(oidPrefix.branch("20"), true, false, tag,
        FieldType.SET_OF));
    last(list).getSyntax().setSubFields(createSyntaxSequenceOfOrSetOf());

    return list;
  }

  private static void certprofileMaxTime(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile max-time", CertLevel.EndEntity,
        "9999y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(DN.CN, 1, 1, ":FQDN", null, null));

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
  } // method certprofileMaxTime

  private static void certprofileFixedPartialSubject(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile fixed subject O and C",
        CertLevel.EndEntity, "365d");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();

    ValueType value = new ValueType();
    value.setText("DE");
    value.setOverridable(true);
    rdnControls.add(createRdn(DN.C, null, null, value));

    value = new ValueType();
    value.setText("fixed xipki.org");
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

  private static void certprofileAppleWwdr(String destFilename) throws Exception {
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
    subField.setSubFields(Arrays.asList(subsubField));

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
    subField.setSubFields(Arrays.asList(subsubField));

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
    subField.setSubFields(Arrays.asList(subsubField));

    syntax.setSubFields(subFields);

    marshall(profile, destFilename, true);
  } // method certprofileAppleWwdr

  private static void certprofileGmt0015(String destFilename) throws Exception {
    String desc = "certprofile GMT 0015";
    X509ProfileType profile = getBaseProfile(desc, CertLevel.EndEntity, "5y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1));
    rdnControls.add(createRdn(Extn.id_GMT_0015_ICRegistrationNumber, 0, 1));
    rdnControls.add(createRdn(Extn.id_GMT_0015_IdentityCode, 0, 1));
    rdnControls.add(createRdn(Extn.id_GMT_0015_InsuranceNumber, 0, 1));
    rdnControls.add(createRdn(Extn.id_GMT_0015_OrganizationCode, 0, 1));
    rdnControls.add(createRdn(Extn.id_GMT_0015_TaxationNumber, 0, 1));

    // Extensions
    // Extensions - controls
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

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth},
        null));

    // Extension id_GMT_0015_ICRegistrationNumber
    ASN1ObjectIdentifier[] gmtOids = new ASN1ObjectIdentifier[] {
        Extn.id_GMT_0015_ICRegistrationNumber,
        Extn.id_GMT_0015_IdentityCode,
        Extn.id_GMT_0015_InsuranceNumber,
        Extn.id_GMT_0015_OrganizationCode,
        Extn.id_GMT_0015_TaxationNumber};
    for (ASN1ObjectIdentifier m : gmtOids) {
      list.add(createExtension(m, true, false));
      last(list).setPermittedInRequest(true);
    }

    marshall(profile, destFilename, true);
  } // method certprofileGmt0012

  private static void certprofileExtended(String destFilename) throws Exception {
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
        createTlsFeature(
            new TlsExtensionType[]{TlsExtensionType.STATUS_REQUEST,
                TlsExtensionType.CLIENT_CERTIFICATE_URL}));

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

  private static RdnType createRdn(ASN1ObjectIdentifier type, int min, int max) {
    return createRdn(type, min, max, null, null, null);
  }

  private static RdnType createRdn(ASN1ObjectIdentifier type, int min, int max,
      String regex, String prefix, String suffix) {
    return createRdn(type, min, max, regex, prefix, suffix, null);
  }

  private static RdnType createRdn(ASN1ObjectIdentifier type, int min, int max,
      String regex, String prefix, String suffix, String group) {
    RdnType ret = new RdnType();
    ret.setType(createOidType(type));
    ret.setMinOccurs(min);
    ret.setMaxOccurs(max);

    if (regex != null) {
      ret.setRegex(regex);
    }

    if (StringUtil.isNotBlank(prefix)) {
      ret.setPrefix(prefix);
    }

    if (StringUtil.isNotBlank(suffix)) {
      ret.setSuffix(suffix);
    }

    if (StringUtil.isNotBlank(group)) {
      ret.setGroup(group);
    }

    if (NOT_IN_SUBJECT_RDNS.contains(type)) {
      ret.setNotInSubject(Boolean.TRUE);
    }

    return ret;
  } // method createRdn

  private static RdnType createRdn(ASN1ObjectIdentifier type,
      String regex, String group, ValueType value) {
    RdnType ret = new RdnType();
    ret.setType(createOidType(type));
    ret.setMinOccurs(1);
    ret.setMaxOccurs(1);
    ret.setValue(value);

    if (regex != null) {
      ret.setRegex(regex);
    }

    if (StringUtil.isNotBlank(group)) {
      ret.setGroup(group);
    }

    return ret;
  } // method createRdn

  private static ExtensionType createExtension(ASN1ObjectIdentifier type, boolean required,
      boolean critical) {
    return createExtension(type, required, critical, null);
  }

  private static ExtensionType createExtension(ASN1ObjectIdentifier type, boolean required,
      boolean critical, String description) {
    ExtensionType ret = new ExtensionType();
    // attributes
    ret.setRequired(required);
    ret.setPermittedInRequest(REQUEST_EXTENSIONS.contains(type));
    // children
    ret.setType(createOidType(type, description));
    ret.setCritical(critical);
    return ret;
  }

  private static ExtensionType createConstantExtension(ASN1ObjectIdentifier type, boolean required,
      boolean critical, Tag tag, FieldType fieldType, String value) {
    ExtensionType ret = new ExtensionType();
    // attributes
    ret.setRequired(required);
    ret.setPermittedInRequest(false);
    // children
    String desc = "custom constant extension " + fieldType.getText();
    if (tag != null) {
      desc += " (" + tag.getValue() + ", " + (tag.isExplicit() ? "EXPLICIT)" : "IMPLICIT)");
    }
    ret.setType(createOidType(type, desc));
    ret.setCritical(critical);

    ConstantExtnValue constantExtn = new ConstantExtnValue(fieldType);
    ret.setConstant(constantExtn);
    if (value != null) {
      constantExtn.setValue(value);
    }

    if (tag != null) {
      constantExtn.setTag(tag);
    }

    return ret;
  }

  private static ExtensionType createSyntaxExtension(ASN1ObjectIdentifier type, boolean required,
      boolean critical, Tag tag, FieldType fieldType) {
    ExtensionType ret = new ExtensionType();
    // attributes
    ret.setRequired(required);
    ret.setPermittedInRequest(true);
    // children
    String desc = "custom syntax extension " + fieldType.getText();
    if (tag != null) {
      desc += " (" + tag.getValue() + ", " + (tag.isExplicit() ? "EXPLICIT)" : "IMPLICIT)");
    }
    ret.setType(createOidType(type, desc));
    ret.setCritical(critical);

    ExtnSyntax extnSyntax = new ExtnSyntax(fieldType);
    if (tag != null) {
      extnSyntax.setTag(tag);
    }

    ret.setSyntax(extnSyntax);

    return ret;
  }

  private static ExtensionType.KeyUsage createKeyUsage(KeyUsage[] requiredUsages,
      KeyUsage[] optionalUsages) {
    ExtensionType.KeyUsage extValue = new ExtensionType.KeyUsage();
    if (requiredUsages != null) {
      for (KeyUsage m : requiredUsages) {
        ExtensionType.KeyUsage.Usage usage = new ExtensionType.KeyUsage.Usage();
        usage.setValue(m);
        usage.setRequired(true);
        extValue.getUsages().add(usage);
      }
    }
    if (optionalUsages != null) {
      for (KeyUsage m : optionalUsages) {
        ExtensionType.KeyUsage.Usage usage = new ExtensionType.KeyUsage.Usage();
        usage.setValue(m);
        usage.setRequired(false);
        extValue.getUsages().add(usage);
      }
    }

    return extValue;
  }

  // CHECKSTYLE:SKIP
  private static AuthorityKeyIdentifier createAKIwithSerialAndSerial() {
    AuthorityKeyIdentifier akiType = new AuthorityKeyIdentifier();
    akiType.setUseIssuerAndSerial(true);
    return akiType;

  }

  private static AuthorityInfoAccess createAuthorityInfoAccess() {
    AuthorityInfoAccess extnValue = new AuthorityInfoAccess();
    extnValue.setIncludeCaIssuers(true);
    extnValue.setIncludeOcsp(true);
    extnValue.setCaIssuersProtocols(new HashSet<>(Arrays.asList("http")));
    extnValue.setOcspProtocols(new HashSet<>(Arrays.asList("http")));
    return extnValue;
  }

  private static CrlDistributionPoints createCrlDistibutoionPoints() {
    CrlDistributionPoints extnValue = new CrlDistributionPoints();
    extnValue.setProtocols(new HashSet<>(Arrays.asList("http")));
    return extnValue;
  }

  private static BasicConstraints createBasicConstraints(int pathLen) {
    BasicConstraints extValue = new BasicConstraints();
    extValue.setPathLen(pathLen);
    return extValue;
  }

  private static ExtendedKeyUsage createExtendedKeyUsage(
      ASN1ObjectIdentifier[] requiredUsages, ASN1ObjectIdentifier[] optionalUsages) {
    ExtendedKeyUsage extValue = new ExtendedKeyUsage();
    if (requiredUsages != null) {
      List<ASN1ObjectIdentifier> oids = Arrays.asList(requiredUsages);
      oids = sortOidList(oids);
      for (ASN1ObjectIdentifier usage : oids) {
        extValue.getUsages().add(createSingleExtKeyUsage(usage, true));
      }
    }

    if (optionalUsages != null) {
      List<ASN1ObjectIdentifier> oids = Arrays.asList(optionalUsages);
      oids = sortOidList(oids);
      for (ASN1ObjectIdentifier usage : oids) {
        extValue.getUsages().add(createSingleExtKeyUsage(usage, false));
      }
    }

    return extValue;
  }

  private static ExtendedKeyUsage.Usage createSingleExtKeyUsage(
      ASN1ObjectIdentifier usage, boolean required) {
    ExtendedKeyUsage.Usage type = new ExtendedKeyUsage.Usage();
    type.setOid(usage.getId());
    type.setRequired(required);
    String desc = getDescription(usage);
    if (desc != null) {
      type.setDescription(desc);
    }
    return type;
  }

  private static Restriction createRestriction(DirectoryStringType type, String text) {
    Restriction extValue = new Restriction();
    extValue.setType(type);
    extValue.setText(text);
    return extValue;
  }

  private static AdditionalInformation createAdditionalInformation(DirectoryStringType type,
      String text) {
    AdditionalInformation extValue = new AdditionalInformation();
    extValue.setType(type);
    extValue.setText(text);
    return extValue;
  }

  private static PrivateKeyUsagePeriod createPrivateKeyUsagePeriod(String validity) {
    PrivateKeyUsagePeriod extValue = new PrivateKeyUsagePeriod();
    extValue.setValidity(validity);
    return extValue;
  }

  private static QcStatements createQcStatements(boolean requireRequestExt) {
    QcStatements extValue = new QcStatements();
    QcStatementType statement = new QcStatementType();

    // QcCompliance
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcCompliance));
    extValue.getQcStatements().add(statement);

    // QC SCD
    statement = new QcStatementType();
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcSSCD));
    extValue.getQcStatements().add(statement);

    // QC RetentionPeriod
    statement = new QcStatementType();
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcRetentionPeriod));
    QcStatementValueType statementValue = new QcStatementValueType();
    statementValue.setQcRetentionPeriod(10);
    statement.setStatementValue(statementValue);
    extValue.getQcStatements().add(statement);

    // QC LimitValue
    statement = new QcStatementType();
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcLimitValue));
    statementValue = new QcStatementValueType();

    QcEuLimitValueType euLimit = new QcEuLimitValueType();
    euLimit.setCurrency("EUR");
    Range2Type rangeAmount = new Range2Type();
    int min = 100;
    rangeAmount.setMin(min);
    rangeAmount.setMax(requireRequestExt ? 200 : min);
    euLimit.setAmount(rangeAmount);

    Range2Type rangeExponent = new Range2Type();
    min = 10;
    rangeExponent.setMin(min);
    rangeExponent.setMax(requireRequestExt ? 20 : min);
    euLimit.setExponent(rangeExponent);

    statementValue.setQcEuLimitValue(euLimit);
    statement.setStatementValue(statementValue);
    extValue.getQcStatements().add(statement);

    // QC PDS
    statement = new QcStatementType();
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcPDS));
    extValue.getQcStatements().add(statement);
    statementValue = new QcStatementValueType();
    statement.setStatementValue(statementValue);
    List<PdsLocationType> pdsLocations = new LinkedList<>();
    statementValue.setPdsLocations(pdsLocations);

    PdsLocationType pdsLocation = new PdsLocationType();
    pdsLocations.add(pdsLocation);
    pdsLocation.setUrl("http://pki.example.org/pds/en");
    pdsLocation.setLanguage("en");

    pdsLocation = new PdsLocationType();
    pdsLocations.add(pdsLocation);
    pdsLocation.setUrl("http://pki.example.org/pds/de");
    pdsLocation.setLanguage("de");

    // QC Constant value
    statement = new QcStatementType();
    statement.setStatementId(createOidType(new ASN1ObjectIdentifier("1.2.3.4.5"), "dummy"));
    statementValue = new QcStatementValueType();
    DescribableBinary value = new DescribableBinary();
    try {
      value.setValue(DERNull.INSTANCE.getEncoded());
    } catch (IOException ex) {
      throw new IllegalStateException(ex);
    }
    value.setDescription("DER NULL");
    statementValue.setConstant(value);
    statement.setStatementValue(statementValue);
    extValue.getQcStatements().add(statement);

    return extValue;
  } // method createQcStatements

  private static BiometricInfo createBiometricInfo() {
    BiometricInfo extValue = new BiometricInfo();

    // type
    // predefined image (0)
    BiometricTypeType type = new BiometricTypeType();
    extValue.getTypes().add(type);

    DescribableInt predefined = new DescribableInt();
    predefined.setValue(0);
    predefined.setDescription("image");
    type.setPredefined(predefined);

    // predefined handwritten-signature(1)
    type = new BiometricTypeType();
    predefined = new DescribableInt();
    predefined.setValue(1);
    predefined.setDescription("handwritten-signature");
    type.setPredefined(predefined);
    extValue.getTypes().add(type);

    // OID
    type = new BiometricTypeType();
    type.setOid(createOidType(new ASN1ObjectIdentifier("1.2.3.4.5.6"), "dummy biometric type"));
    extValue.getTypes().add(type);

    // hash algorithm
    HashAlgo[] hashAlgos = new HashAlgo[]{HashAlgo.SHA256, HashAlgo.SHA384};
    for (HashAlgo hashAlgo : hashAlgos) {
      extValue.getHashAlgorithms().add(createOidType(hashAlgo.getOid(), hashAlgo.getName()));
    }

    extValue.setIncludeSourceDataUri(TripleState.required);
    return extValue;
  } // method createBiometricInfo

  private static AuthorizationTemplate createAuthorizationTemplate() {
    AuthorizationTemplate extValue = new AuthorizationTemplate();
    extValue.setType(createOidType(new ASN1ObjectIdentifier("1.2.3.4.5"), "dummy type"));
    DescribableBinary accessRights = new DescribableBinary();
    accessRights.setDescription("dummy access rights");
    accessRights.setValue(new byte[]{1, 2, 3, 4});
    extValue.setAccessRights(accessRights);

    return extValue;
  }

  private static ValidityModel createValidityModel(DescribableOid modelId) {
    ValidityModel extValue = new ValidityModel();
    extValue.setModelId(modelId);
    return extValue;
  }

  private static CertificatePolicies createCertificatePolicies(
      Map<ASN1ObjectIdentifier, String> policies) {
    if (policies == null || policies.isEmpty()) {
      return null;
    }

    CertificatePolicies extValue = new CertificatePolicies();
    List<CertificatePolicyInformationType> pis = extValue.getCertificatePolicyInformations();
    for (ASN1ObjectIdentifier oid : policies.keySet()) {
      CertificatePolicyInformationType single = new CertificatePolicyInformationType();
      pis.add(single);
      single.setPolicyIdentifier(createOidType(oid));

      List<PolicyQualifier> qualifiers = new ArrayList<>(1);
      String cpsUri = policies.get(oid);
      if (cpsUri != null) {
        PolicyQualifier qualifier = new PolicyQualifier();
        qualifier.setType(PolicyQualfierType.cpsUri);
        qualifier.setValue(cpsUri);
        qualifiers.add(qualifier);
      }
      single.setPolicyQualifiers(qualifiers);
    }

    return extValue;
  }

  private static String getDescription(ASN1ObjectIdentifier oid) {
    return ObjectIdentifiers.getName(oid);
  }

  private static PolicyIdMappingType createPolicyIdMapping(
      ASN1ObjectIdentifier issuerPolicyId, ASN1ObjectIdentifier subjectPolicyId) {
    PolicyIdMappingType ret = new PolicyIdMappingType();
    ret.setIssuerDomainPolicy(createOidType(issuerPolicyId));
    ret.setSubjectDomainPolicy(createOidType(subjectPolicyId));

    return ret;
  }

  private static PolicyConstraints createPolicyConstraints(Integer inhibitPolicyMapping,
      Integer requireExplicitPolicy) {
    PolicyConstraints ret = new PolicyConstraints();
    if (inhibitPolicyMapping != null) {
      ret.setInhibitPolicyMapping(inhibitPolicyMapping);
    }

    if (requireExplicitPolicy != null) {
      ret.setRequireExplicitPolicy(requireExplicitPolicy);
    }
    return ret;
  }

  private static NameConstraints createNameConstraints() {
    NameConstraints ret = new NameConstraints();
    List<GeneralSubtreeType> permitted = new LinkedList<>();
    ret.setPermittedSubtrees(permitted);

    GeneralSubtreeType single = new GeneralSubtreeType();
    single.setBase(new GeneralSubtreeType.Base());
    single.getBase().setDirectoryName("O=example organization, C=DE");
    permitted.add(single);

    List<GeneralSubtreeType> excluded = new LinkedList<>();
    single = new GeneralSubtreeType();
    excluded.add(single);

    single.setBase(new GeneralSubtreeType.Base());
    single.getBase().setDirectoryName("OU=bad OU, O=example organization, C=DE");
    ret.setExcludedSubtrees(excluded);

    return ret;
  }

  private static InhibitAnyPolicy createInhibitAnyPolicy(int skipCerts) {
    InhibitAnyPolicy ret = new InhibitAnyPolicy();
    ret.setSkipCerts(skipCerts);
    return ret;
  }

  private static DescribableOid createOidType(ASN1ObjectIdentifier oid) {
    return createOidType(oid, null);
  }

  private static DescribableOid createOidType(ASN1ObjectIdentifier oid, String description) {
    DescribableOid ret = new DescribableOid();
    ret.setOid(oid.getId());

    String desc = (description == null) ? getDescription(oid) : description;
    if (desc != null) {
      ret.setDescription(desc);
    }
    return ret;
  }

  private static X509ProfileType getBaseCabProfile(String description, CertLevel certLevel,
      String validity) {
    return getBaseCabProfile(description, certLevel, validity, false, false);
  }

  private static X509ProfileType getBaseCabProfile(String description, CertLevel certLevel,
      String validity, boolean useMidnightNotBefore, boolean incSerialNumber) {
    X509ProfileType profile = new X509ProfileType();

    profile.setMetadata(createDescription(description));

    profile.setCertDomain(CertDomain.CABForumBR);
    profile.setCertLevel(certLevel);
    profile.setMaxSize(6000 * 3 / 4);
    profile.setVersion(X509CertVersion.v3);
    profile.setValidity(validity);
    profile.setNotBeforeTime(useMidnightNotBefore ? "midnight" : "current");

    profile.setSerialNumberInReq(false);

    if (certLevel == CertLevel.EndEntity) {
      profile.setKeypairGeneration(new KeypairGenerationType());
      profile.getKeypairGeneration().setInheritCA(true);
    }

    // SignatureAlgorithms
    List<String> algos = new LinkedList<>();
    profile.setSignatureAlgorithms(algos);

    String[] sigHashAlgos = new String[]{"SHA512", "SHA384", "SHA256"};

    String[] algoPart2s = new String[]{"withRSA", "withDSA", "withECDSA", "withRSAandMGF1"};
    for (String part2 : algoPart2s) {
      for (String hashAlgo : sigHashAlgos) {
        algos.add(hashAlgo + part2);
      }
    }

    // Subject
    Subject subject = new Subject();
    profile.setSubject(subject);
    subject.setKeepRdnOrder(false);
    subject.setIncSerialNumber(incSerialNumber);

    // Key
    profile.setKeyAlgorithms(createCabKeyAlgorithms());

    return profile;
  } // method getBaseProfile

  private static X509ProfileType getBaseProfile(String description, CertLevel certLevel,
      String validity) {
    return getBaseProfile(description, certLevel, validity, false, false);
  }

  private static X509ProfileType getBaseProfile(String description, CertLevel certLevel,
      String validity, boolean useMidnightNotBefore, boolean incSerialNumber) {
    X509ProfileType profile = new X509ProfileType();

    profile.setMetadata(createDescription(description));

    profile.setCertLevel(certLevel);
    profile.setMaxSize(4500);
    profile.setVersion(X509CertVersion.v3);
    profile.setValidity(validity);
    profile.setNotBeforeTime(useMidnightNotBefore ? "midnight" : "current");

    profile.setSerialNumberInReq(false);

    if (certLevel == CertLevel.EndEntity) {
      profile.setKeypairGeneration(new KeypairGenerationType());
      profile.getKeypairGeneration().setInheritCA(true);
    }

    // SignatureAlgorithms
    List<String> algos = new LinkedList<>();
    profile.setSignatureAlgorithms(algos);

    String[] sigHashAlgos = new String[]{"SHA3-512", "SHA3-384", "SHA3-256", "SHA3-224",
      "SHA512", "SHA384", "SHA256", "SHA1"};

    String[] algoPart2s = new String[]{"withRSA", "withDSA", "withECDSA", "withRSAandMGF1"};
    for (String part2 : algoPart2s) {
      for (String hashAlgo : sigHashAlgos) {
        algos.add(hashAlgo + part2);
      }
    }

    String part2 = "withPlainECDSA";
    for (String hashAlgo : sigHashAlgos) {
      if (!hashAlgo.startsWith("SHA3-")) {
        algos.add(hashAlgo + part2);
      }
    }

    algos.add("SM3withSM2");
    algos.add("Ed25519");
    algos.add("Ed448");

    // Subject
    Subject subject = new Subject();
    profile.setSubject(subject);
    subject.setKeepRdnOrder(false);
    subject.setIncSerialNumber(incSerialNumber);

    ASN1ObjectIdentifier[] curveIds = (CertLevel.EndEntity != certLevel) ? null :
      new ASN1ObjectIdentifier[] {SECObjectIdentifiers.secp256r1,
        TeleTrusTObjectIdentifiers.brainpoolP256r1, GMObjectIdentifiers.sm2p256v1};

    // Key
    profile.setKeyAlgorithms(createKeyAlgorithms(curveIds, certLevel));

    return profile;
  } // method getBaseProfile

  private static X509ProfileType getEeBaseProfileForEdwardsOrMontgomeryCurves(String description,
      String validity, boolean edwards, boolean curve25519) {
    X509ProfileType profile = new X509ProfileType();

    profile.setMetadata(createDescription(description));

    profile.setCertLevel(CertLevel.EndEntity);
    profile.setMaxSize(4500);
    profile.setVersion(X509CertVersion.v3);
    profile.setValidity(validity);
    profile.setNotBeforeTime("current");

    profile.setSerialNumberInReq(false);

    KeypairGenerationType kpGen = new KeypairGenerationType();
    profile.setKeypairGeneration(kpGen);
    KeyType keyType;
    ASN1ObjectIdentifier algorithm;
    if (edwards) {
      keyType = curve25519 ? KeyType.ed25519 : KeyType.ed448;
      algorithm = curve25519 ? EdECConstants.id_Ed25519 : EdECConstants.id_Ed448;
    } else {
      keyType = curve25519 ? KeyType.x25519 : KeyType.x448;
      algorithm = curve25519 ? EdECConstants.id_X25519 : EdECConstants.id_X448;
    }
    kpGen.setAlgorithm(createOidType(algorithm));
    kpGen.setKeyType(keyType);

    // SignatureAlgorithm
    List<String> algos = new LinkedList<>();
    profile.setSignatureAlgorithms(algos);
    algos.add("Ed25519");
    algos.add("Ed448");

    // Subject
    Subject subject = new Subject();
    profile.setSubject(subject);
    subject.setKeepRdnOrder(false);
    subject.setIncSerialNumber(false);

    // KeyUsage

    KeyUsage[] usages = edwards
      ? new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.contentCommitment}
      : new KeyUsage[]{KeyUsage.keyAgreement};

    List<AlgorithmType> keyAlgorithms = createEdwardsOrMontgomeryKeyAlgorithms(
        edwards, !edwards, curve25519, !curve25519);

    profile.setKeyAlgorithms(keyAlgorithms);
    List<ExtensionType> extensions = profile.getExtensions();
    extensions.add(createExtension(Extension.keyUsage, true, true));
    last(extensions).setKeyUsage(createKeyUsage(usages, null));

    return profile;
  } // method getEeBaseProfileForEdwardsOrMontgomeryCurves

  private static List<AlgorithmType> createCabKeyAlgorithms() {
    List<AlgorithmType> list = new LinkedList<>();

    // RSA
    list.addAll(createRSAKeyAlgorithms());

    // DSA
    list.add(new AlgorithmType());
    last(list).getAlgorithms().add(createOidType(X9ObjectIdentifiers.id_dsa, "DSA"));
    last(list).setParameters(new KeyParametersType());

    DsaParametersType dsaParams = new DsaParametersType();
    last(list).getParameters().setDsa(dsaParams);

    List<Range> plengths = new LinkedList<>();
    dsaParams.setPlengths(plengths);

    plengths.add(createRange(2048));
    plengths.add(createRange(3072));

    List<Range> qlengths = new LinkedList<>();
    dsaParams.setQlengths(qlengths);
    qlengths.add(createRange(224));
    qlengths.add(createRange(256));

    // EC
    list.add(new AlgorithmType());

    last(list).getAlgorithms().add(createOidType(X9ObjectIdentifiers.id_ecPublicKey, "EC"));
    last(list).setParameters(new KeyParametersType());

    EcParametersType ecParams = new EcParametersType();
    last(list).getParameters().setEc(ecParams);

    ASN1ObjectIdentifier[] curveIds = new ASN1ObjectIdentifier[] {SECObjectIdentifiers.secp256r1,
        SECObjectIdentifiers.secp384r1, SECObjectIdentifiers.secp521r1};
    List<DescribableOid> curves = new LinkedList<>();
    ecParams.setCurves(curves);

    for (ASN1ObjectIdentifier curveId : curveIds) {
      String name = AlgorithmUtil.getCurveName(curveId);
      curves.add(createOidType(curveId, name));
    }

    ecParams.setPointEncodings(Arrays.asList(((byte) 4)));

    return list;
  } // method createCabKeyAlgorithms

  private static List<AlgorithmType> createKeyAlgorithms(
      ASN1ObjectIdentifier[] curveIds, CertLevel certLevel) {
    List<AlgorithmType> list = new LinkedList<>();

    // RSA
    list.addAll(createRSAKeyAlgorithms());

    // DSA
    list.add(new AlgorithmType());
    last(list).getAlgorithms().add(createOidType(X9ObjectIdentifiers.id_dsa, "DSA"));
    last(list).setParameters(new KeyParametersType());

    DsaParametersType dsaParams = new DsaParametersType();
    last(list).getParameters().setDsa(dsaParams);

    List<Range> plengths = new LinkedList<>();
    dsaParams.setPlengths(plengths);

    plengths.add(createRange(1024));
    plengths.add(createRange(2048));
    plengths.add(createRange(3072));

    List<Range> qlengths = new LinkedList<>();
    dsaParams.setQlengths(qlengths);
    qlengths.add(createRange(160));
    qlengths.add(createRange(224));
    qlengths.add(createRange(256));

    // EC
    list.add(new AlgorithmType());

    last(list).getAlgorithms().add(createOidType(X9ObjectIdentifiers.id_ecPublicKey, "EC"));
    last(list).setParameters(new KeyParametersType());

    EcParametersType ecParams = new EcParametersType();
    last(list).getParameters().setEc(ecParams);

    if (curveIds != null && curveIds.length > 0) {
      List<DescribableOid> curves = new LinkedList<>();
      ecParams.setCurves(curves);

      for (ASN1ObjectIdentifier curveId : curveIds) {
        String name = AlgorithmUtil.getCurveName(curveId);
        curves.add(createOidType(curveId, name));
      }
    }

    ecParams.setPointEncodings(Arrays.asList(((byte) 4)));

    // EdDSA
    if (certLevel == CertLevel.RootCA || certLevel == CertLevel.SubCA) {
      list.addAll(createEdwardsOrMontgomeryKeyAlgorithms(true, false, true, true));
    }

    return list;
  } // method createKeyAlgorithms

  private static List<AlgorithmType> createEdwardsOrMontgomeryKeyAlgorithms(
      boolean edwards, boolean montgomery, boolean curve25519, boolean curve448) {
    List<AlgorithmType> list = new LinkedList<>();

    List<ASN1ObjectIdentifier> oids = new LinkedList<>();
    if (edwards) {
      if (curve25519) {
        oids.add(EdECConstants.id_Ed25519);
      }

      if (curve448) {
        oids.add(EdECConstants.id_Ed448);
      }
    } else {
      if (curve25519) {
        oids.add(EdECConstants.id_X25519);
      }

      if (curve448) {
        oids.add(EdECConstants.id_X448);
      }
    }

    for (ASN1ObjectIdentifier oid : oids) {
      list.add(new AlgorithmType());
      last(list).getAlgorithms().add(createOidType(oid));
    }

    return list;
  } // method createEdwardsOrMontgomeryKeyAlgorithms

  // CHECKSTYLE:SKIP
  private static List<AlgorithmType> createRSAKeyAlgorithms() {
    List<AlgorithmType> list = new LinkedList<>();

    list.add(new AlgorithmType());
    last(list).getAlgorithms().add(createOidType(PKCSObjectIdentifiers.rsaEncryption, "RSA"));
    last(list).setParameters(new KeyParametersType());

    RsaParametersType rsaParams = new RsaParametersType();
    last(list).getParameters().setRsa(rsaParams);

    rsaParams.getModulusLengths().add(createRange(2048));
    rsaParams.getModulusLengths().add(createRange(3072));
    rsaParams.getModulusLengths().add(createRange(4096));

    return list;
  }

  private static Range createRange(int size) {
    return createRange(size, size);
  }

  private static Range createRange(Integer min, Integer max) {
    Range ret = new Range();
    ret.setMin(min);
    ret.setMax(max);
    return ret;
  }

  private static Map<String, String> createDescription(String details) {
    Map<String, String> map = new HashMap<>();
    map.put("category", "A");
    map.put("details", details);
    return map;
  }

  private static TlsFeature createTlsFeature(TlsExtensionType... features) {
    List<TlsExtensionType> exts = Arrays.asList(features);
    Collections.sort(exts);

    TlsFeature tlsFeature = new TlsFeature();
    for (TlsExtensionType m : exts) {
      DescribableInt dint = new DescribableInt();
      dint.setValue(m.getCode());
      dint.setDescription(m.getName());
      tlsFeature.getFeatures().add(dint);
    }

    return tlsFeature;
  }

  private static SmimeCapabilities createSmimeCapabilities() {
    SmimeCapabilities caps = new SmimeCapabilities();

    // DES-EDE3-CBC
    SmimeCapability cap = new SmimeCapability();
    caps.getCapabilities().add(cap);
    cap.setCapabilityId(createOidType(new ASN1ObjectIdentifier("1.2.840.113549.3.7"),
        "DES-EDE3-CBC"));

    // RC2-CBC keysize 128
    cap = new SmimeCapability();
    caps.getCapabilities().add(cap);
    cap.setCapabilityId(createOidType(new ASN1ObjectIdentifier("1.2.840.113549.3.2"), "RC2-CBC"));
    cap.setParameter(new SmimeCapabilityParameter());
    cap.getParameter().setInteger(BigInteger.valueOf(128));

    // RC2-CBC keysize 64
    cap = new SmimeCapability();
    caps.getCapabilities().add(cap);
    cap.setCapabilityId(createOidType(new ASN1ObjectIdentifier("1.2.840.113549.3.2"), "RC2-CBC"));
    cap.setParameter(new SmimeCapabilityParameter());

    DescribableBinary binary = new DescribableBinary();
    try {
      binary.setValue(new ASN1Integer(64).getEncoded());
      binary.setDescription("INTEGER 64");
    } catch (IOException ex) {
      throw new IllegalStateException(ex.getMessage());
    }
    cap.getParameter().setBinary(binary);

    return caps;
  }

  private static List<ASN1ObjectIdentifier> sortOidList(List<ASN1ObjectIdentifier> oids) {
    Args.notNull(oids, "oids");
    List<String> list = new ArrayList<>(oids.size());
    for (ASN1ObjectIdentifier m : oids) {
      list.add(m.getId());
    }
    Collections.sort(list);

    List<ASN1ObjectIdentifier> sorted = new ArrayList<>(oids.size());
    for (String m : list) {
      for (ASN1ObjectIdentifier n : oids) {
        if (m.equals(n.getId()) && !sorted.contains(n)) {
          sorted.add(n);
        }
      }
    }
    return sorted;
  }

  private static <T> T last(List<T> list) {
    if (list == null || list.isEmpty()) {
      return null;
    } else {
      return list.get(list.size() - 1);
    }

  }
}
