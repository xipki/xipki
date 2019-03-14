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
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.api.profile.Certprofile.X509CertVersion;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.certprofile.xijson.DirectoryStringType;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.AlgorithmType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicyInformationType;
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
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ConstantExtnValue;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ExtendedKeyUsage;
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
import org.xipki.ca.certprofile.xijson.conf.QcStatementType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.PdsLocationType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.QcEuLimitValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.QcStatementValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.Range2Type;
import org.xipki.ca.certprofile.xijson.conf.Subject;
import org.xipki.ca.certprofile.xijson.conf.Subject.RdnType;
import org.xipki.ca.certprofile.xijson.conf.SubjectToSubjectAltNameType;
import org.xipki.ca.certprofile.xijson.conf.X509ProfileType;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.TlsExtensionType;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.TripleState;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

/**
 * TODO.
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

  private static final String REGEX_FQDN =
      "(?=^.{1,254}$)(^(?:(?!\\d+\\.|-)[a-zA-Z0-9_\\-]{1,63}(?<!-)\\.?)+(?:[a-zA-Z]{2,})$)";

  private static final String REGEX_SN = "[\\d]{1,}";

  private static final Set<ASN1ObjectIdentifier> REQUEST_EXTENSIONS;

  static {
    REQUEST_EXTENSIONS = new HashSet<>();
    REQUEST_EXTENSIONS.add(Extension.keyUsage);
    REQUEST_EXTENSIONS.add(Extension.extendedKeyUsage);
    REQUEST_EXTENSIONS.add(Extension.subjectAlternativeName);
    REQUEST_EXTENSIONS.add(Extension.subjectInfoAccess);
  }

  private ProfileConfCreatorDemo() {
  }

  public static void main(String[] args) {
    try {
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
      certprofileExtended("certprofile-extended.json");
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
            SerializerFeature.PrettyFormat, SerializerFeature.SortField);
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

  private static void certprofileRootCa(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile rootca", CertLevel.RootCA, "10y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign},
        new KeyUsage[]{KeyUsage.cRLSign}));

    marshall(profile, destFilename, true);
  } // method certprofileRootCa

  private static void certprofileCross(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile cross", CertLevel.SubCA, "10y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(false));

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
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign},
        new KeyUsage[]{KeyUsage.cRLSign}));

    marshall(profile, destFilename, true);
  } // method certprofileSubCa

  private static void certprofileSubCaComplex(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile subca-complex (with most extensions)",
        CertLevel.SubCA, "8y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1, null, "PREFIX ", " SUFFIX"));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign},
        new KeyUsage[]{KeyUsage.cRLSign}));

    // Certificate Policies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    last(list).setCertificatePolicies(
        createCertificatePolicies(new ASN1ObjectIdentifier("1.2.3.4.5"),
            new ASN1ObjectIdentifier("2.4.3.2.1")));

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
    gn.addOtherNames(createOidType(ObjectIdentifiers.DN.O));

    // SubjectInfoAccess
    list.add(createExtension(Extension.subjectInfoAccess, true, false));
    SubjectInfoAccess subjectInfoAccess = new SubjectInfoAccess();
    last(list).setSubjectInfoAccess(subjectInfoAccess);
    SubjectInfoAccess.Access access = new SubjectInfoAccess.Access();
    subjectInfoAccess.getAccesses().add(access);

    access.setAccessMethod(createOidType(ObjectIdentifiers.Extn.id_ad_caRepository));

    GeneralNameType accessLocation = new GeneralNameType();
    access.setAccessLocation(accessLocation);
    accessLocation.addTags(GeneralNameTag.directoryName,
        GeneralNameTag.uniformResourceIdentifier);

    // Custom Extension
    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.1"), true, false, "custom extension BIT STRING"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.BIT_STRING,
        Base64.encodeToString(new byte[] {1, 2}), null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.2"), true, false, "custom extension BMPSTRING"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.BMPString,
        "A BMP string", null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.3"), true, false, "custom extension BOOLEAN"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.BOOLEAN,
        Boolean.TRUE.toString(), null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.4"), true, false, "custom extension IA5String"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.IA5String,
        "An IA5 string", null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.5"), true, false, "custom extension INTEGER"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.INTEGER,
        "10", null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.6"), true, false, "custom extension NULL"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.NULL,
        null, null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.7"), true, false, "custom extension OCTET STRING"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.OCTET_STRING,
        Base64.encodeToString(new byte[] {3, 4}), null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.8"), true, false, "custom extension OID"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.OID,
        "2.3.4.5", null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.9"), true, false, "custom extension PrintableString"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.PrintableString,
        "A printable string", null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.10"), true, false, "custom extension raw"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.raw,
        Base64.encodeToString(DERNull.INSTANCE.getEncoded()), "DER NULL"));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.11"), true, false, "custom extension TeletexString"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.TeletexString,
        "A teletax string", null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.12"), true, false, "custom extension UTF8String"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.UTF8String,
        "A UTF8 string", null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.13"), true, false, "custom extension ENUMERATED"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.ENUMERATED,
        "2", null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.14"), true, false, "custom extension GeneralizedTime"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.GeneralizedTime,
        new ASN1GeneralizedTime("20180314130102Z").getTimeString(), null));

    list.add(createExtension(
        new ASN1ObjectIdentifier("1.2.3.4.15"), true, false, "custom extension UTCTIME"));
    last(list).setConstant(createConstantExtValue(ConstantExtnValue.Type.UTCTime,
        "190314130102Z", null));

    marshall(profile, destFilename, true);
  } // method certprofileSubCaComplex

  private static void certprofileOcsp(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile ocsp", CertLevel.EndEntity, "5y",
        false, true);

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.organizationIdentifier, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    list.add(createExtension(Extension.freshestCRL, false, false, null));
    list.add(createExtension(
              ObjectIdentifiers.Extn.id_extension_pkix_ocsp_nocheck, false, false, null));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.contentCommitment},
        new KeyUsage[]{KeyUsage.cRLSign}));

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
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

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
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    if (legacy) {
      rdnControls.add(createRdn(ObjectIdentifiers.DN.emailAddress, 1, 1));
    }
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(ObjectIdentifiers.DN.emailAddress));
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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

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
    list.add(createExtension(ObjectIdentifiers.Extn.id_smimeCapabilities, true, false));
    last(list).setSmimeCapabilities(createSmimeCapabilities());

    marshall(profile, destFilename, true);
  } // method certprofileTls

  private static void certprofileTls(String destFilename, boolean incSerial) throws Exception {
    String desc = incSerial ? "certprofile tls-inc-sn (serial number will be added automatically)"
        : "certprofile tls";
    X509ProfileType profile = getBaseProfile(desc, CertLevel.EndEntity, "5y", true, incSerial);

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1, REGEX_FQDN, null, null));

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(ObjectIdentifiers.DN.CN));
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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

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
    list.add(createExtension(ObjectIdentifiers.Extn.id_pe_tlsfeature, true, true));
    last(list).setTlsFeature(createTlsFeature(
        TlsExtensionType.STATUS_REQUEST, TlsExtensionType.CLIENT_CERTIFICATE_URL));

    marshall(profile, destFilename, true);
  } // method certprofileTls

  private static void certprofileTlsC(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile tls-c", CertLevel.EndEntity, "5y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

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
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));

    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 2, 2));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

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
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1, null, null, null, "group1"));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 1, 1, null, null, null, "group1"));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

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
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.organizationIdentifier, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

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
    subject.setKeepRdnOrder(true);
    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.dateOfBirth, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.postalAddress, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.uniqueIdentifier, 1, 1));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

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
    attrTypes.add(createOidType(ObjectIdentifiers.DN.countryOfCitizenship));
    attrTypes.add(createOidType(ObjectIdentifiers.DN.countryOfResidence));
    attrTypes.add(createOidType(ObjectIdentifiers.DN.gender));
    attrTypes.add(createOidType(ObjectIdentifiers.DN.dateOfBirth));
    attrTypes.add(createOidType(ObjectIdentifiers.DN.placeOfBirth));

    // Extension - Admission
    list.add(createExtension(ObjectIdentifiers.Extn.id_extension_admission, true, false));
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
    list.add(createExtension(ObjectIdentifiers.Extn.id_extension_restriction, true, false));
    last(list).setRestriction(
        createRestriction(DirectoryStringType.utf8String, "demo restriction"));

    // additionalInformation
    list.add(createExtension(
              ObjectIdentifiers.Extn.id_extension_additionalInformation, true, false));
    last(list).setAdditionalInformation(createAdditionalInformation(DirectoryStringType.utf8String,
        "demo additional information"));

    // validationModel
    list.add(createExtension(ObjectIdentifiers.Extn.id_extension_validityModel, true, false));
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
    accessMethods.add(ObjectIdentifiers.Extn.id_ad_caRepository);
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

  private static void certprofileMaxTime(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile max-time", CertLevel.EndEntity,
        "9999y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1, REGEX_FQDN, null, null));

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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileMaxTime

  private static void certprofileExtended(String destFilename) throws Exception {
    X509ProfileType profile = getBaseProfile("certprofile extended", CertLevel.EndEntity, "5y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(ObjectIdentifiers.DN.C, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.O, 1, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.OU, 0, 1));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.SN, 0, 1, REGEX_SN, null, null));
    rdnControls.add(createRdn(ObjectIdentifiers.DN.CN, 1, 1, REGEX_FQDN, null, null));

    // SubjectToSubjectAltName
    List<SubjectToSubjectAltNameType> subjectToSubjectAltNames = new LinkedList<>();
    profile.setSubjectToSubjectAltNames(subjectToSubjectAltNames);

    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    subjectToSubjectAltNames.add(s2sType);
    s2sType.setSource(createOidType(ObjectIdentifiers.DN.CN));
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
    last(list).setAuthorityKeyIdentifier(createAuthorityKeyIdentifier(true));

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
    list.add(createExtension(ObjectIdentifiers.Extn.id_pe_tlsfeature, true, true));
    last(list).setTlsFeature(
        createTlsFeature(
            new TlsExtensionType[]{TlsExtensionType.STATUS_REQUEST,
                TlsExtensionType.CLIENT_CERTIFICATE_URL}));

    // Extensions - SMIMECapabilities
    list.add(createExtension(ObjectIdentifiers.Extn.id_smimeCapabilities, true, false));
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

  private static AuthorityKeyIdentifier createAuthorityKeyIdentifier(
      boolean includeSerialAndSerial) {
    AuthorityKeyIdentifier akiType = new AuthorityKeyIdentifier();
    akiType.setIncludeIssuerAndSerial(includeSerialAndSerial);
    return akiType;

  }

  private static AuthorityInfoAccess createAuthorityInfoAccess() {
    AuthorityInfoAccess extnValue = new AuthorityInfoAccess();
    extnValue.setIncludeCaIssuers(true);
    extnValue.setIncludeOcsp(true);
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
    statement.setStatementId(createOidType(ObjectIdentifiers.Extn.id_etsi_qcs_QcCompliance));
    extValue.getQcStatements().add(statement);

    // QC SCD
    statement = new QcStatementType();
    statement.setStatementId(createOidType(ObjectIdentifiers.Extn.id_etsi_qcs_QcSSCD));
    extValue.getQcStatements().add(statement);

    // QC RetentionPeriod
    statement = new QcStatementType();
    statement.setStatementId(createOidType(ObjectIdentifiers.Extn.id_etsi_qcs_QcRetentionPeriod));
    QcStatementValueType statementValue = new QcStatementValueType();
    statementValue.setQcRetentionPeriod(10);
    statement.setStatementValue(statementValue);
    extValue.getQcStatements().add(statement);

    // QC LimitValue
    statement = new QcStatementType();
    statement.setStatementId(createOidType(ObjectIdentifiers.Extn.id_etsi_qcs_QcLimitValue));
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
    statement.setStatementId(createOidType(ObjectIdentifiers.Extn.id_etsi_qcs_QcPDS));
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

  private static CertificatePolicies createCertificatePolicies(ASN1ObjectIdentifier... policyOids) {
    if (policyOids == null || policyOids.length == 0) {
      return null;
    }

    CertificatePolicies extValue = new CertificatePolicies();
    List<CertificatePolicyInformationType> pis = extValue.getCertificatePolicyInformations();
    for (ASN1ObjectIdentifier oid : policyOids) {
      CertificatePolicyInformationType single = new CertificatePolicyInformationType();
      pis.add(single);
      single.setPolicyIdentifier(createOidType(oid));
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

  private static ConstantExtnValue createConstantExtValue(ConstantExtnValue.Type type,
      String value, String desc) {
    ConstantExtnValue extValue = new ConstantExtnValue(type, value);
    if (StringUtil.isNotBlank(desc)) {
      extValue.setDescription(desc);
    }
    return extValue;
  }

  private static X509ProfileType getBaseProfile(String description, CertLevel certLevel,
      String validity) {
    return getBaseProfile(description, certLevel, validity, false, false);
  }

  private static X509ProfileType getBaseProfile(String description, CertLevel certLevel,
      String validity, boolean useMidnightNotBefore, boolean incSerialNumber) {
    X509ProfileType profile = new X509ProfileType();

    profile.setMetadata(createDescription(description));

    profile.setCertLevel(certLevel);
    profile.setMaxSize(5000);
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

    // Subject
    Subject subject = new Subject();
    profile.setSubject(subject);
    subject.setKeepRdnOrder(false);
    subject.setIncSerialNumber(incSerialNumber);

    ASN1ObjectIdentifier[] curveIds = (CertLevel.EndEntity != certLevel) ? null :
      new ASN1ObjectIdentifier[] {SECObjectIdentifiers.secp256r1,
        TeleTrusTObjectIdentifiers.brainpoolP256r1, GMObjectIdentifiers.sm2p256v1};

    // Key
    profile.setKeyAlgorithms(createKeyAlgorithms(curveIds));

    return profile;
  } // method getBaseProfile

  private static List<AlgorithmType> createKeyAlgorithms(ASN1ObjectIdentifier[] curveIds) {
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

    return list;
  } // method createKeyAlgorithms

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
