// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.certprofile.xijson.conf.ConstantExtnValue;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableBinary;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.ca.certprofile.xijson.conf.extn.AuthorityInfoAccess;
import org.xipki.ca.certprofile.xijson.conf.extn.AuthorityKeyIdentifier;
import org.xipki.ca.certprofile.xijson.conf.extn.BasicConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.BiometricInfo;
import org.xipki.ca.certprofile.xijson.conf.extn.BiometricInfo.BiometricTypeType;
import org.xipki.ca.certprofile.xijson.conf.extn.CertificatePolicies;
import org.xipki.ca.certprofile.xijson.conf.extn.CertificatePolicies.CertificatePolicyInformationType;
import org.xipki.ca.certprofile.xijson.conf.extn.CertificatePolicies.PolicyQualfierType;
import org.xipki.ca.certprofile.xijson.conf.extn.CertificatePolicies.PolicyQualifier;
import org.xipki.ca.certprofile.xijson.conf.extn.CrlDistributionPoints;
import org.xipki.ca.certprofile.xijson.conf.extn.ExtendedKeyUsage;
import org.xipki.ca.certprofile.xijson.conf.extn.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.extn.KeyUsage;
import org.xipki.ca.certprofile.xijson.conf.extn.NameConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyMappings.PolicyIdMappingType;
import org.xipki.ca.certprofile.xijson.conf.extn.PrivateKeyUsagePeriod;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements.PdsLocationType;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements.QcEuLimitValueType;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements.QcStatementType;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements.QcStatementValueType;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements.Range2Type;
import org.xipki.ca.certprofile.xijson.conf.extn.SmimeCapabilities;
import org.xipki.ca.certprofile.xijson.conf.extn.SmimeCapabilities.SmimeCapability;
import org.xipki.ca.certprofile.xijson.conf.extn.SmimeCapabilities.SmimeCapabilityParameter;
import org.xipki.ca.certprofile.xijson.conf.extn.TlsFeature;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.TlsExtensionType;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.TripleState;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Extension builder for xijson configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class ExtensionConfBuilder {

  private static final Set<ASN1ObjectIdentifier> REQUIRED_REQUEST_EXTENSIONS;

  private static final Set<ASN1ObjectIdentifier> OPTIONAL_REQUEST_EXTENSIONS;

  static {
    REQUIRED_REQUEST_EXTENSIONS = CollectionUtil.asUnmodifiableSet(
        Extension.subjectAlternativeName,      Extension.subjectDirectoryAttributes,
        Extension.subjectInfoAccess,           Extension.biometricInfo);

    OPTIONAL_REQUEST_EXTENSIONS = CollectionUtil.asUnmodifiableSet(
        Extension.keyUsage, Extension.extendedKeyUsage, Extension.qCStatements);
  } // method static

  public static List<ExtensionType> createConstantExtensions(ASN1ObjectIdentifier oidPrefix) {
    List<ExtensionType> list = new LinkedList<>();

    Date now = Date.from(Instant.now());
    // Custom Constant Extension Value
    list.add(createConstantExtension(oidPrefix.branch("1"), true, false,
        new DERBitString(new byte[] {1, 2})));
    list.add(createConstantExtension(oidPrefix.branch("2"), true, false,
        new DERBMPString("A BMP string")));
    list.add(createConstantExtension(oidPrefix.branch("3"), true, false,
        ASN1Boolean.TRUE));
    list.add(createConstantExtension(oidPrefix.branch("4"), true, false,
        new DERIA5String("An IA5 string")));
    list.add(createConstantExtension(oidPrefix.branch("5"), true, false,
        new ASN1Integer(BigInteger.valueOf(10))));
    list.add(createConstantExtension(oidPrefix.branch("6"), true, false,
        DERNull.INSTANCE));
    list.add(createConstantExtension(oidPrefix.branch("7"), true, false,
        new DEROctetString(new byte[] {3, 4})));
    list.add(createConstantExtension(oidPrefix.branch("8"), true, false,
        new ASN1ObjectIdentifier("2.3.4.5")));
    list.add(createConstantExtension(oidPrefix.branch("9"), true, false,
        new DERPrintableString("A printable string")));
    list.add(createConstantExtension(oidPrefix.branch("11"), true, false,
       new DERT61String("A teletax string")));
    list.add(createConstantExtension(oidPrefix.branch("12"), true, false,
        new DERUTF8String("A UTF8 string")));
    list.add(createConstantExtension(oidPrefix.branch("13"), true, false,
        new ASN1Enumerated(2)));
    list.add(createConstantExtension(oidPrefix.branch("14"), true, false,
        new ASN1GeneralizedTime(now)));
    list.add(createConstantExtension(oidPrefix.branch("15"), true, false,
        new DERUTCTime(now)));
    list.add(createConstantExtension(oidPrefix.branch("16"), true, false,
        new X500Name("CN=abc,C=DE")));

    return list;
  } // method createConstantExtensions

  public static ExtensionType createExtension(ASN1ObjectIdentifier type, boolean required, boolean critical) {
    return createExtension(type, required, critical, null);
  }

  public static ExtensionType createExtension(
      ASN1ObjectIdentifier type, boolean required, boolean critical, String description) {
    ExtensionType ret = new ExtensionType();
    // attributes
    ret.setRequired(required);

    if (REQUIRED_REQUEST_EXTENSIONS.contains(type)) {
      ret.setInRequest(TripleState.required);
    } else if (OPTIONAL_REQUEST_EXTENSIONS.contains(type)) {
      ret.setInRequest(TripleState.optional);
    }

    // children
    ret.setType(createOidType(type, description));
    ret.setCritical(critical);
    return ret;
  }

  public static ExtensionType createConstantExtension(
      ASN1ObjectIdentifier type, boolean required, boolean critical, ASN1Object value) {
    ExtensionType ret = new ExtensionType();
    // attributes
    ret.setRequired(required);
    ret.setType(createOidType(type, value.getClass().getSimpleName()));
    ret.setCritical(critical);

    ConstantExtnValue constantExtn = new ConstantExtnValue();
    ret.setConstant(constantExtn);
    try {
      constantExtn.setValue(Base64.encodeToString(value.getEncoded()));
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }

    return ret;
  } // method createConstantExtension

  public static KeyUsage createKeyUsage(
      org.xipki.security.KeyUsage[] requiredUsages, org.xipki.security.KeyUsage[] optionalUsages) {
    KeyUsage extValue = new KeyUsage();
    if (requiredUsages != null) {
      for (org.xipki.security.KeyUsage m : requiredUsages) {
        KeyUsage.Usage usage = new KeyUsage.Usage();
        usage.setValue(m.name());
        usage.setRequired(true);
        extValue.getUsages().add(usage);
      }
    }
    if (optionalUsages != null) {
      for (org.xipki.security.KeyUsage m : optionalUsages) {
        KeyUsage.Usage usage = new KeyUsage.Usage();
        usage.setValue(m.name());
        usage.setRequired(false);
        extValue.getUsages().add(usage);
      }
    }

    return extValue;
  } // method createKeyUsage

  public static AuthorityKeyIdentifier createAKIwithSerialAndSerial() {
    AuthorityKeyIdentifier akiType = new AuthorityKeyIdentifier();
    akiType.setUseIssuerAndSerial(true);
    return akiType;
  } // method createAKIwithSerialAndSerial

  public static AuthorityInfoAccess createAuthorityInfoAccess() {
    AuthorityInfoAccess extnValue = new AuthorityInfoAccess();
    extnValue.setIncludeCaIssuers(true);
    extnValue.setIncludeOcsp(true);
    extnValue.setCaIssuersProtocols(new HashSet<>(Collections.singletonList("http")));
    extnValue.setOcspProtocols(new HashSet<>(Collections.singletonList("http")));
    return extnValue;
  } // method createAuthorityInfoAccess

  public static CrlDistributionPoints createCrlDistibutoionPoints() {
    CrlDistributionPoints extnValue = new CrlDistributionPoints();
    extnValue.setProtocols(new HashSet<>(Collections.singletonList("http")));
    return extnValue;
  }

  public static BasicConstraints createBasicConstraints(int pathLen) {
    BasicConstraints extValue = new BasicConstraints();
    extValue.setPathLen(pathLen);
    return extValue;
  }

  public static ExtendedKeyUsage createExtendedKeyUsage(
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
  } // method createExtendedKeyUsage

  public static ExtendedKeyUsage.Usage createSingleExtKeyUsage(ASN1ObjectIdentifier usage, boolean required) {
    ExtendedKeyUsage.Usage type = new ExtendedKeyUsage.Usage();
    type.setOid(usage.getId());
    type.setRequired(required);
    String desc = getDescription(usage);
    if (desc != null) {
      type.setDescription(desc);
    }
    return type;
  } // method createSingleExtKeyUsage

  public static PrivateKeyUsagePeriod createPrivateKeyUsagePeriod(String validity) {
    PrivateKeyUsagePeriod extValue = new PrivateKeyUsagePeriod();
    extValue.setValidity(validity);
    return extValue;
  }

  public static QcStatements createQcStatements(boolean requireRequestExt) {
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
    pdsLocation.setUrl("http://pki.myorg.org/pds/en");
    pdsLocation.setLanguage("en");

    pdsLocation = new PdsLocationType();
    pdsLocations.add(pdsLocation);
    pdsLocation.setUrl("http://pki.myorg.org/pds/de");
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

  public static BiometricInfo createBiometricInfo() {
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
      extValue.getHashAlgorithms().add(createOidType(hashAlgo.getOid(), hashAlgo.getJceName()));
    }

    extValue.setIncludeSourceDataUri(TripleState.required);
    return extValue;
  } // method createBiometricInfo

  public static CertificatePolicies createCertificatePolicies(Map<ASN1ObjectIdentifier, String> policies) {
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
  } // method createCertificatePolicies

  private static String getDescription(ASN1ObjectIdentifier oid) {
    return ObjectIdentifiers.getName(oid);
  }

  public static PolicyIdMappingType createPolicyIdMapping(
      ASN1ObjectIdentifier issuerPolicyId, ASN1ObjectIdentifier subjectPolicyId) {
    PolicyIdMappingType ret = new PolicyIdMappingType();
    ret.setIssuerDomainPolicy(createOidType(issuerPolicyId));
    ret.setSubjectDomainPolicy(createOidType(subjectPolicyId));

    return ret;
  } // method createPolicyIdMapping

  public static PolicyConstraints createPolicyConstraints(Integer inhibitPolicyMapping, Integer requireExplicitPolicy) {
    PolicyConstraints ret = new PolicyConstraints();
    if (inhibitPolicyMapping != null) {
      ret.setInhibitPolicyMapping(inhibitPolicyMapping);
    }

    if (requireExplicitPolicy != null) {
      ret.setRequireExplicitPolicy(requireExplicitPolicy);
    }
    return ret;
  } // method createPolicyConstraints

  public static NameConstraints createNameConstraints() {
    NameConstraints ret = new NameConstraints();
    List<GeneralSubtreeType> permitted = new LinkedList<>();
    ret.setPermittedSubtrees(permitted);

    GeneralSubtreeType single = new GeneralSubtreeType();
    single.setBase(new GeneralSubtreeType.Base());
    single.getBase().setDirectoryName("O=myorg organization, C=DE");
    permitted.add(single);

    List<GeneralSubtreeType> excluded = new LinkedList<>();
    single = new GeneralSubtreeType();
    excluded.add(single);

    single.setBase(new GeneralSubtreeType.Base());
    single.getBase().setDirectoryName("OU=bad OU, O=myorg organization, C=DE");
    ret.setExcludedSubtrees(excluded);

    return ret;
  } // method createNameConstraints

  public static InhibitAnyPolicy createInhibitAnyPolicy(int skipCerts) {
    InhibitAnyPolicy ret = new InhibitAnyPolicy();
    ret.setSkipCerts(skipCerts);
    return ret;
  } // method createInhibitAnyPolicy

  public static DescribableOid createOidType(ASN1ObjectIdentifier oid) {
    return createOidType(oid, null);
  }

  public static DescribableOid createOidType(ASN1ObjectIdentifier oid, String description) {
    DescribableOid ret = new DescribableOid();
    ret.setOid(oid.getId());

    String desc = (description == null) ? getDescription(oid) : description;
    if (desc != null) {
      ret.setDescription(desc);
    }
    return ret;
  } // method

  public static Map<String, String> createDescription(String details) {
    Map<String, String> map = new HashMap<>();
    map.put("category", "A");
    map.put("details", details);
    return map;
  } // method createDescription

  public static TlsFeature createTlsFeature(TlsExtensionType... features) {
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
  } // method createTlsFeature

  public static SmimeCapabilities createSmimeCapabilities() {
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
  } // method createSmimeCapabilities

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
  } // method sortOidList

  private static ExtensionType last(List<ExtensionType> list) {
    return list.get(list.size() - 1);
  } // method last
}
