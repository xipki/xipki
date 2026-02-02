// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.id.AccessMethodID;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.ca.api.profile.id.ExtendedKeyUsageID;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.api.profile.id.QCStatementID;
import org.xipki.ca.certprofile.xijson.conf.ConstantExtnValue;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.ca.certprofile.xijson.conf.RdnType;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyMappings;
import org.xipki.ca.certprofile.xijson.conf.extn.PrivateKeyUsagePeriod;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements;
import org.xipki.ca.certprofile.xijson.conf.extn.SubjectInfoAccess;
import org.xipki.security.OIDs;
import org.xipki.security.pkix.KeyUsage;
import org.xipki.security.pkix.TlsExtensionType;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.TripleState;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Demo the creation of json configuration for complex certificates.
 *
 * @author Lijun Liao (xipki)
 */

public class ComplexProfileConfDemo extends ProfileConfBuilder {

  public static void main(String[] args) {
    try {
      certprofileSubCaComplex(qa_dir + "/certprofile-subca-complex.json");
      certprofileEeComplex   (qa_dir + "/certprofile-ee-complex.json");
      certprofileMultipleOus (qa_dir + "/certprofile-multiple-ous.json");
      certprofileExtended    (qa_dir + "/certprofile-extended.json");
      certprofileConstantExt (qa_dir + "/certprofile-constant-ext.json");
      certprofileFixedPartialSubject(
          qa_dir + "/certprofile-fixed-partial-subject.json");
      certprofileQc(qa_dir + "/certprofile-qc.json");
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void certprofileSubCaComplex(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile subca-complex (with most extensions)",
        CertLevel.SubCA, "8y", KeypairGenMode.INHERITCA, AllowKeyMode.ALL_SIGN);

    // Subject
    addRdns(profile,
        rdn  (AttributeType.C),
        rdn  (AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN, 1, 1, null));

    // Extensions
    List<ExtensionType> list = profile.extensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));
    last(list).setBasicConstraints(createBasicConstraints(1));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign},
        null, profile.keyAlgorithms()));

    // Certificate Policies
    list.add(createExtension(ExtensionID.certificatePolicies, true, false));

    Map<CertificatePolicyID, String> policies = new HashMap<>();
    policies.put(CertificatePolicyID.ofOidOrName("1.2.3.4.5"),
        "http://myorg.org/ca1-cps");
    policies.put(CertificatePolicyID.ofOidOrName("2.4.3.2.1"), null);
    last(list).setCertificatePolicies(createCertificatePolicies(policies));

    // Policy Mappings
    list.add(createExtension(ExtensionID.policyMappings, true, true));

    List<PolicyMappings.PolicyIdMappingType> policyMappings =
        new ArrayList<>(2);
    policyMappings.add(createPolicyIdMapping(
        CertificatePolicyID.ofOidOrName("1.1.1.1.1"),
        CertificatePolicyID.ofOidOrName("2.1.1.1.1")));
    policyMappings.add(createPolicyIdMapping(
        CertificatePolicyID.ofOidOrName("1.1.1.1.2"),
        CertificatePolicyID.ofOidOrName("2.1.1.1.2")));

    last(list).setPolicyMappings(new PolicyMappings(policyMappings));

    // Policy Constraints
    list.add(createExtension(ExtensionID.policyConstraints, true, true));
    last(list).setPolicyConstraints(createPolicyConstraints(2, 2));

    // Name Constraints
    list.add(createExtension(ExtensionID.nameConstraints, true, true));
    last(list).setNameConstraints(createNameConstraints());

    // Inhibit anyPolicy
    list.add(createExtension(ExtensionID.inhibitAnyPolicy, true, true));
    last(list).setInhibitAnyPolicy(createInhibitAnyPolicy(1));

    // SubjectAltName
    list.add(createExtension(ExtensionID.subjectAltName, true, true));
    GeneralNameType gn = new GeneralNameType(Arrays.asList(
        GeneralNameTag.rfc822Name, GeneralNameTag.DNSName,
        GeneralNameTag.directoryName, GeneralNameTag.ediPartyName,
        GeneralNameTag.uri, GeneralNameTag.IPAddress,
        GeneralNameTag.registeredID, GeneralNameTag.otherName));
    last(list).setSubjectAltName(gn);

    // SubjectInfoAccess
    list.add(createExtension(ExtensionID.subjectInfoAccess, true, false));

    SubjectInfoAccess.Access access = new SubjectInfoAccess.Access(
        AccessMethodID.caRepository,
        new GeneralNameType(Arrays.asList(
            GeneralNameTag.directoryName, GeneralNameTag.uri)));

    last(list).setSubjectInfoAccess(new SubjectInfoAccess(List.of(access)));

    // PrivateKeyUsagePeriod
    list.add(createExtension(ExtensionID.privateKeyUsagePeriod, true, false));
    last(list).setPrivateKeyUsagePeriod(new PrivateKeyUsagePeriod("10y"));

    // BiometricInfo
    /*
    list.add(createExtension(ExtensionID.biometricInfo, true, false));
    BiometricInfo biometricInfo = new BiometricInfo();
    // TODO
    last(list).setBiometricInfo(biometricInfo);
     */

    // QCStatements
    /*
    list.add(createExtension(ExtensionID.qcStatements, true, false));
    QcStatements qcStatements = new QcStatements();
    // TODO
    last(list).setQcStatements(qcStatements);
     */

    marshall(profile, destFilename, true);
  } // method certprofileSubCaComplex

  private static void certprofileMultipleOus(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile("certprofile multiple-ous",
        CertLevel.EndEntity, "5y", KeypairGenMode.INHERITCA,
        AllowKeyMode.ALL);

    // Subject
    addRdns(profile,
        rdn  (AttributeType.country),
        rdn  (AttributeType.O),
        rdn  (AttributeType.OU, 2, 2),
        rdn01(AttributeType.serialNumber),
        rdn  (AttributeType.commonName));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.extensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.contentCommitment, KeyUsage.digitalSignature,
            KeyUsage.keyAgreement, KeyUsage.keyEncipherment,
            KeyUsage.dataEncipherment}, null,
        profile.keyAlgorithms()));

    marshall(profile, destFilename, true);
  } // method certprofileMultipleOus

  private static void certprofileEeComplex(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile ee-complex", CertLevel.EndEntity,
        "5y", KeypairGenMode.INHERITCA, AllowKeyMode.RSA, AllowKeyMode.ALL);
    profile.setNotBeforeTime("midnight");
    // Subject
    addRdns(profile,
        rdn  (AttributeType.commonName),
        rdn  (AttributeType.country),
        rdn  (AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.serialNumber),
        rdn01(AttributeType.postalAddress),
        rdn01(AttributeType.dateOfBirth),
        rdn  (AttributeType.userid),
        rdn  (AttributeType.jurIncorporationCountry),
        rdn  (AttributeType.jurIncorporationLocality),
        rdn  (AttributeType.jurIncorporationState));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.extensions();

    // Extensions - controls
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, false));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment, KeyUsage.keyAgreement},
        null, profile.keyAlgorithms()));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.serverAuth},
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.clientAuth}));

    // Extensions - tlsFeature
    list.add(createExtension(ExtensionID.tlsFeature, true, false));
    last(list).setTlsFeature(createTlsFeature(
        TlsExtensionType.STATUS_REQUEST,
        TlsExtensionType.CLIENT_CERTIFICATE_URL));

    // SubjectAltName
    list.add(createExtension(ExtensionID.subjectAltName, true, true));
    GeneralNameType gn = new GeneralNameType(Arrays.asList(
        GeneralNameTag.rfc822Name, GeneralNameTag.DNSName,
        GeneralNameTag.directoryName, GeneralNameTag.ediPartyName,
        GeneralNameTag.uri, GeneralNameTag.IPAddress,
        GeneralNameTag.registeredID, GeneralNameTag.otherName));
    last(list).setSubjectAltName(gn);

    // SubjectInfoAccess
    list.add(createExtension(ExtensionID.subjectInfoAccess, true, false));

    List<ASN1ObjectIdentifier> accessMethods = new LinkedList<>();
    accessMethods.add(OIDs.Extn.id_ad_caRepository);
    for (int i = 0; i < 10; i++) {
      accessMethods.add(new ASN1ObjectIdentifier("2.3.4." + (i + 1)));
    }

    List<SubjectInfoAccess.Access> accesses =
        new ArrayList<>(accessMethods.size());
    for (ASN1ObjectIdentifier accessMethod : accessMethods) {
      GeneralNameType accessLocation = new GeneralNameType(Arrays.asList(
          GeneralNameTag.rfc822Name, GeneralNameTag.DNSName,
          GeneralNameTag.directoryName, GeneralNameTag.ediPartyName,
          GeneralNameTag.uri, GeneralNameTag.IPAddress,
          GeneralNameTag.registeredID, GeneralNameTag.otherName));
      accesses.add(new SubjectInfoAccess.Access(
          AccessMethodID.ofOid(accessMethod), accessLocation));
    }

    SubjectInfoAccess subjectInfoAccess = new SubjectInfoAccess(accesses);
    last(list).setSubjectInfoAccess(subjectInfoAccess);

    marshall(profile, destFilename, true);
  } // method certprofileEeComplex

  private static void certprofileConstantExt(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile constant-extension",
        CertLevel.EndEntity, "5y", KeypairGenMode.INHERITCA, AllowKeyMode.ALL);

    // Subject
    profile.setKeepSubjectOrder(true);
    addRdns(profile,
        rdn  (AttributeType.CN),
        rdn  (AttributeType.C),
        rdn  (AttributeType.O),
        rdn01(AttributeType.OU));

    // Extensions
    // Extensions - general
    List<ExtensionType> list = profile.extensions();

    // Extensions - controls
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, false));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment, KeyUsage.keyAgreement},
        null, profile.keyAlgorithms()));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.serverAuth},
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.clientAuth}));

    // Custom Constant Extension Value
    list.addAll(createConstantExtensions());

    marshall(profile, destFilename, true);
  } // method certprofileConstantExt

  private static void certprofileFixedPartialSubject(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile fixed subject O and C",
        CertLevel.EndEntity, "365d", KeypairGenMode.INHERITCA,
        AllowKeyMode.ALL);

    // Subject
    List<RdnType> subject = profile.subject();

    subject.add(rdn01(AttributeType.C));
    subject.add(rdn  (AttributeType.O,  null, "fixed myorg.org"));
    subject.add(rdn01(AttributeType.OU));
    subject.add(rdn01(AttributeType.SN));
    subject.add(rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.extensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment, KeyUsage.keyAgreement},
        null, profile.keyAlgorithms()));

    marshall(profile, destFilename, true);
  } // method certprofileFixedPartialSubject

  private static void certprofileExtended(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile("certprofile extended",
        CertLevel.EndEntity, "5y",
        KeypairGenMode.INHERITCA, AllowKeyMode.ALL);

    // Subject
    addRdns(profile,
        rdn  (AttributeType.country),
        rdn  (AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.serialNumber),
        rdn  (AttributeType.commonName, 1, 1, ":FQDN", null));

    // Extensions
    // Extensions - general

    // Extensions - controls
    List<ExtensionType> list = profile.extensions();
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - SubjectAltNames
    list.add(createExtension(ExtensionID.subjectAltName, true, false));
    GeneralNameType gn = new GeneralNameType(Arrays.asList(
        GeneralNameTag.DNSName, GeneralNameTag.IPAddress));
    last(list).setSubjectAltName(gn);

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment, KeyUsage.keyAgreement},
        null, profile.keyAlgorithms()));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.serverAuth},
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.clientAuth}));

    // Extensions - tlsFeature
    list.add(createExtension(ExtensionID.tlsFeature, true, false));
    last(list).setTlsFeature(createTlsFeature(
        TlsExtensionType.STATUS_REQUEST,
        TlsExtensionType.CLIENT_CERTIFICATE_URL));

    // Extensions - SMIMECapabilities
    list.add(createExtension(ExtensionID.smimeCapabilities, true, false));
    last(list).setSmimeCapabilities(createSmimeCapabilities());

    // Extensions - 1.2.3.4.1 (demo_without_conf)
    list.add(createExtension(ExtensionID.ofOidOrName("1.2.3.4.1"),
        true, false));

    // cannot validate due to some additional customized extensions.
    marshall(profile, destFilename, false);
  } // method certprofileExtended

  private static void certprofileQc(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile("certprofile QC",
        CertLevel.EndEntity, "1000d",
        KeypairGenMode.INHERITCA, AllowKeyMode.ALL);

    // Subject
    addRdns(profile,
        rdn(AttributeType.country),
        rdn(AttributeType.O),
        rdn01(AttributeType.organizationIdentifier),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.serialNumber),
        rdn  (AttributeType.commonName));

    // Extensions
    // Extensions - general

    // Extensions - controls
    List<ExtensionType> list = profile.extensions();
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment, KeyUsage.keyAgreement},
        null, profile.keyAlgorithms()));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extKeyUsage, true, true));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.timestamping}, null));

    // Extensions - PrivateKeyUsage
    list.add(createExtension(ExtensionID.privateKeyUsagePeriod, true, false));
    last(list).setPrivateKeyUsagePeriod(new PrivateKeyUsagePeriod("3y"));

    // Extensions - QCStatements
    list.add(createExtension(ExtensionID.qcStatements, true, false));
    last(list).setInRequest(TripleState.optional);

    List<QcStatements.QcStatementType> types = new LinkedList<>();
    QcStatements.QcStatementType type = new QcStatements.QcStatementType(
        QCStatementID.etsi_qcs_QcCompliance, null);
    types.add(type);

    type = new QcStatements.QcStatementType(
        QCStatementID.etsi_qcs_QcSSCD, null);
    types.add(type);

    type = new QcStatements.QcStatementType(
        QCStatementID.etsi_qcs_QcRetentionPeriod,
        new QcStatements.QcStatementValueType(null, 10, null, null));
    types.add(type);

    QcStatements.QcEuLimitValueType limitValue =
        new QcStatements.QcEuLimitValueType("EUR",
            new QcStatements.Range2Type(100, 100),
            new QcStatements.Range2Type(10, 10));
    type = new QcStatements.QcStatementType(
        QCStatementID.etsi_qcs_QcLimitValue,
        new QcStatements.QcStatementValueType(null, null, limitValue, null));
    types.add(type);

    List<QcStatements.PdsLocationType> locations = new LinkedList<>();
    locations.add(new QcStatements.PdsLocationType(
        "http://pki.myorg.org/pds/en", "en"));
    locations.add(new QcStatements.PdsLocationType(
        "http://pki.myorg.org/pds/de", "de"));
    type = new QcStatements.QcStatementType(
        QCStatementID.etsi_qcs_QcPDS,
        new QcStatements.QcStatementValueType(
            null, null, null, locations));
    types.add(type);

    ConstantExtnValue constValue = new ConstantExtnValue(
        ConstantExtnValue.Type.ASN1, Base64.decode("BQA="));
    type = new QcStatements.QcStatementType(
        QCStatementID.ofOid(new ASN1ObjectIdentifier("1.2.3.4.5")),
        new QcStatements.QcStatementValueType(constValue, null, null, null));
    types.add(type);

    QcStatements qcStatements = new QcStatements(types);
    last(list).setQcStatements(qcStatements);

    // cannot validate due to some additional customized extensions.
    marshall(profile, destFilename, false);
  } // method certprofileQc

}
