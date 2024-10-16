// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.xipki.ca.api.profile.BaseCertprofile;
import org.xipki.ca.api.profile.Certprofile.AuthorityInfoAccessControl;
import org.xipki.ca.api.profile.Certprofile.CrlDistributionPointsControl;
import org.xipki.ca.api.profile.Certprofile.ExtKeyUsageControl;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.ca.api.profile.Certprofile.GeneralNameMode;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.api.profile.Certprofile.KeyUsageControl;
import org.xipki.ca.api.profile.Certprofile.SubjectControl;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.SubjectKeyIdentifierControl;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.ca.certprofile.xijson.conf.SubjectToSubjectAltNameType;
import org.xipki.ca.certprofile.xijson.conf.X509ProfileType;
import org.xipki.ca.certprofile.xijson.conf.extn.AuthorityInfoAccess;
import org.xipki.ca.certprofile.xijson.conf.extn.AuthorityKeyIdentifier;
import org.xipki.ca.certprofile.xijson.conf.extn.BasicConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.BiometricInfo;
import org.xipki.ca.certprofile.xijson.conf.extn.CertificatePolicies;
import org.xipki.ca.certprofile.xijson.conf.extn.CrlDistributionPoints;
import org.xipki.ca.certprofile.xijson.conf.extn.ExtendedKeyUsage;
import org.xipki.ca.certprofile.xijson.conf.extn.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.extn.KeyUsage;
import org.xipki.ca.certprofile.xijson.conf.extn.NameConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyMappings;
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
import org.xipki.ca.certprofile.xijson.conf.extn.SubjectDirectoryAttributs;
import org.xipki.ca.certprofile.xijson.conf.extn.SubjectInfoAccess;
import org.xipki.ca.certprofile.xijson.conf.extn.SubjectInfoAccess.Access;
import org.xipki.ca.certprofile.xijson.conf.extn.TlsFeature;
import org.xipki.pki.BadCertTemplateException;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;

/**
 * Extensions configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class XijsonExtensions {

  private AuthorityInfoAccessControl aiaControl;

  private CrlDistributionPointsControl crlDpControl;

  private CrlDistributionPointsControl freshestCrlControl;

  private Map<ASN1ObjectIdentifier, GeneralNameTag> subjectToSubjectAltNameModes;

  private Set<GeneralNameMode> subjectAltNameModes;

  private Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> subjectInfoAccessModes;

  private BiometricInfoOption biometricInfo;

  private org.bouncycastle.asn1.x509.CertificatePolicies certificatePolicies;

  private final Map<ASN1ObjectIdentifier, ExtensionValue> constantExtensions;

  private Set<ExtKeyUsageControl> extendedKeyusages;

  private final Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls;

  private boolean useIssuerAndSerialInAki;

  private SubjectKeyIdentifierControl subjectKeyIdentifier;

  private ExtensionValue inhibitAnyPolicy;

  private Set<KeyUsageControl> keyusages;

  private ExtensionValue nameConstraints;

  private Integer pathLen;

  private ExtensionValue policyConstraints;

  private ExtensionValue policyMappings;

  private Validity privateKeyUsagePeriod;

  private ExtensionValue qcStatments;

  private List<QcStatementOption> qcStatementsOption;

  private ExtensionValue smimeCapabilities;

  private ExtensionValue tlsFeature;

  private SubjectDirectoryAttributesControl subjectDirAttrsControl;

  XijsonExtensions(XijsonCertprofile certProfile, X509ProfileType conf, SubjectControl subjectControl)
      throws CertprofileException {
    Args.notNull(subjectControl, "subjectControl");

    // Extensions
    Map<String, ExtensionType> extensions = Args.notNull(conf, "conf").buildExtensions();

    // Extension controls
    this.extensionControls = conf.buildExtensionControls();
    Set<ASN1ObjectIdentifier> extnIds = new HashSet<>(this.extensionControls.keySet());

    // SubjectToSubjectAltName
    initSubjectToSubjectAltNames(conf.getSubjectToSubjectAltNames());

    // AuthorityInfoAccess
    initAuthorityInfoAccess(extnIds, extensions);

    // AuthorityKeyIdentifier
    initAuthorityKeyIdentifier(extnIds, extensions);

    // SubjectKeyIdentifier
    initSubjectKeyIdentifier(extnIds, extensions);

    // BasicConstraints
    initBasicConstraints(extnIds, extensions);

    // BiometricInfo
    initBiometricInfo(extnIds, extensions);

    // Certificate Policies
    initCertificatePolicies(extnIds, extensions);

    // CRLDistributionPoints
    initCrlDistributionPoints(extnIds, extensions);

    // ExtendedKeyUsage
    initExtendedKeyUsage(extnIds, extensions);

    // CRLDistributionPoints
    initFreshestCrl(extnIds, extensions);

    // Inhibit anyPolicy
    initInhibitAnyPolicy(extnIds, extensions);

    // KeyUsage
    initKeyUsage(extnIds, extensions);

    // Name Constraints
    initNameConstraints(extnIds, extensions);

    // Policy Constraints
    initPolicyConstraints(extnIds, extensions);

    // Policy Mappings
    initPolicyMappings(extnIds, extensions);

    // PrivateKeyUsagePeriod
    initPrivateKeyUsagePeriod(extnIds, extensions);

    // QCStatements
    initQcStatements(extnIds, extensions);

    // SMIMECapabilities
    initSmimeCapabilities(extnIds, extensions);

    // SubjectAltNameMode
    initSubjectAlternativeName(extnIds, extensions);

    // SubjectInfoAccess
    initSubjectInfoAccess(extnIds, extensions);

    // TlsFeature
    initTlsFeature(extnIds, extensions);

    // SubjectDirectoryAttributes
    initSubjectDirAttrs(extnIds, extensions);

    // constant extensions
    this.constantExtensions = conf.buildConstantExtesions();
    if (this.constantExtensions != null) {
      extnIds.removeAll(this.constantExtensions.keySet());
    }

    // validate the configuration

    /*
     * RFC 5280, Section 4.1.2.7 Subject
     *    Conforming implementations generating new certificates with
     *    electronic mail addresses MUST use the rfc822Name in the subject
     *    alternative name extension (Section 4.2.1.6) to describe such
     *    identities.  Simultaneous inclusion of the emailAddress attribute in
     *    the subject distinguished name to support legacy implementations is
     *    deprecated but permitted.
     *
     * Make sure that if email address is contained in subject, it must be duplicated
     * in the SubjectAltName extension as rfc822Name.
     */
    if (subjectControl.getControl(ObjectIdentifiers.DN.emailAddress) != null) {
      ASN1ObjectIdentifier type = ObjectIdentifiers.DN.emailAddress;

      if (subjectToSubjectAltNameModes == null || subjectToSubjectAltNameModes.get(type) == null) {
        throw new CertprofileException("subjectToSubjectAltNames for " + ObjectIdentifiers.oidToDisplayName(type)
            + " must be configured if subject RDN emailAddress is permitted");
      }

      GeneralNameTag nameTag = subjectToSubjectAltNameModes.get(type);
      if (nameTag != GeneralNameTag.rfc822Name) {
        throw new CertprofileException("For the RDN " + ObjectIdentifiers.DN.emailAddress.getId()
            + ", only target SubjectAltName type rfc822Name is permitted, but not " + nameTag);
      }
    }

    if (subjectToSubjectAltNameModes != null) {
      ASN1ObjectIdentifier type = Extension.subjectAlternativeName;
      if (!extensionControls.containsKey(type)) {
        throw new CertprofileException("subjectToSubjectAltNames cannot be configured if extension"
            + " subjectAltNames is not permitted");
      }

      if (subjectAltNameModes != null) {
        for (Entry<ASN1ObjectIdentifier, GeneralNameTag> entry : subjectToSubjectAltNameModes.entrySet()) {
          GeneralNameTag nameTag = entry.getValue();

          boolean allowed = false;
          for (GeneralNameMode m : subjectAltNameModes) {
            if (m.getTag() == nameTag) {
              allowed = true;
              break;
            }
          }

          if (!allowed) {
            throw new CertprofileException("target SubjectAltName type " + nameTag + " is not allowed");
          }
        }
      }
    }

    // Remove the extension processed not by the Certprofile, but by the CA
    Arrays.asList(
        Extension.issuerAlternativeName,     Extension.authorityInfoAccess,  Extension.cRLDistributionPoints,
        Extension.freshestCRL,               Extension.subjectKeyIdentifier, Extension.subjectInfoAccess,
        Extn.id_extension_pkix_ocsp_nocheck, Extn.id_SCTs).forEach(extnIds::remove);

    if (!extnIds.isEmpty()) {
      throw new CertprofileException("Cannot process the extensions: " + extnIds);
    }
  } // method initialize0

  private void initSubjectToSubjectAltNames(List<SubjectToSubjectAltNameType> list) throws CertprofileException {
    if (CollectionUtil.isEmpty(list)) {
      return;
    }

    subjectToSubjectAltNameModes = new HashMap<>();
    for (SubjectToSubjectAltNameType m : list) {
      GeneralNameTag targetTag = m.getTarget();
      switch (targetTag) {
        case rfc822Name:
        case DNSName:
        case uniformResourceIdentifier:
        case IPAddress:
        case directoryName:
        case registeredID:
          break;
        default:
          throw new CertprofileException("unsupported target tag " + targetTag);
      }

      subjectToSubjectAltNameModes.put(new ASN1ObjectIdentifier(m.getSource().getOid()), targetTag);
    }
  } // method initSubjectToSubjectAltNames

  private void initAuthorityInfoAccess(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.authorityInfoAccess;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      AuthorityInfoAccess extConf = getExtension(type, extensions).getAuthorityInfoAccess();
      this.aiaControl = (extConf == null)
        ? new AuthorityInfoAccessControl(false, true, null, null)
        : new AuthorityInfoAccessControl(extConf.isIncludeCaIssuers(), extConf.isIncludeOcsp(),
              extConf.getCaIssuersProtocols(), extConf.getOcspProtocols());
    }
  } // method initAuthorityInfoAccess

  private void initAuthorityKeyIdentifier(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.authorityKeyIdentifier;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      AuthorityKeyIdentifier extConf = getExtension(type, extensions).getAuthorityKeyIdentifier();
      this.useIssuerAndSerialInAki = extConf != null && extConf.isUseIssuerAndSerial();
    }
  } // method initAuthorityKeyIdentifier

  private void initSubjectKeyIdentifier(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.subjectKeyIdentifier;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      this.subjectKeyIdentifier = getExtension(type, extensions).getSubjectKeyIdentifier();
    }
  } // method initSubjectKeyIdentifier

  private void initBasicConstraints(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.basicConstraints;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      BasicConstraints extConf = getExtension(type, extensions).getBasicConstraints();
      if (extConf == null) {
        extConf = getExtension(type, extensions).getBasicConstraints();
      }
      if (extConf != null) {
        this.pathLen = extConf.getPathLen();
      }
    }
  } // method initBasicConstraints

  private void initBiometricInfo(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.biometricInfo;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      BiometricInfo extConf = getExtension(type, extensions).getBiometricInfo();
      if (extConf != null) {
        try {
          this.biometricInfo = new BiometricInfoOption(extConf);
        } catch (NoSuchAlgorithmException ex) {
          throw new CertprofileException("NoSuchAlgorithmException: " + ex.getMessage());
        }
      }
    }
  } // method initBiometricInfo

  private void initCertificatePolicies(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.certificatePolicies;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      CertificatePolicies extConf = getExtension(type, extensions).getCertificatePolicies();
      if (extConf != null) {
        certificatePolicies = extConf.toXiCertificatePolicies();
      }
    }
  } // method initCertificatePolicies

  private void initCrlDistributionPoints(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.cRLDistributionPoints;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      CrlDistributionPoints extConf = getExtension(type, extensions).getCrlDistributionPoints();
      crlDpControl = new CrlDistributionPointsControl(extConf == null ? null : extConf.getProtocols());
    }
  } // method initCrlDistributionPoints

  private void initExtendedKeyUsage(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.extendedKeyUsage;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      ExtendedKeyUsage extConf = getExtension(type, extensions).getExtendedKeyUsage();
      if (extConf != null) {
        this.extendedKeyusages = extConf.toXiExtKeyUsageOptions();
      }
    }
  } // method initExtendedKeyUsage

  private void initFreshestCrl(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.freshestCRL;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      CrlDistributionPoints extConf = getExtension(type, extensions).getFreshestCrl();
      freshestCrlControl = new CrlDistributionPointsControl(extConf == null ? null : extConf.getProtocols());
    }
  } // method initFreshestCrl

  private void initInhibitAnyPolicy(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.inhibitAnyPolicy;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      InhibitAnyPolicy extConf = getExtension(type, extensions).getInhibitAnyPolicy();
      if (extConf != null) {
        int skipCerts = extConf.getSkipCerts();
        if (skipCerts < 0) {
          throw new CertprofileException("negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
        }
        this.inhibitAnyPolicy = new ExtensionValue(critical(type), new ASN1Integer(BigInteger.valueOf(skipCerts)));
      }
    }
  } // method initInhibitAnyPolicy

  private void initKeyUsage(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.keyUsage;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      KeyUsage extConf = getExtension(type, extensions).getKeyUsage();
      if (extConf != null) {
        this.keyusages = extConf.toXiKeyUsageOptions();
      }
    }
  } // method initKeyUsage

  private void initNameConstraints(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.nameConstraints;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      NameConstraints extConf = getExtension(type, extensions).getNameConstraints();
      if (extConf != null) {
        this.nameConstraints = new ExtensionValue(critical(type), extConf.toXiNameConstraints());
      }
    }
  } // method initNameConstraints

  private void initPrivateKeyUsagePeriod(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.privateKeyUsagePeriod;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      PrivateKeyUsagePeriod extConf = getExtension(type, extensions).getPrivateKeyUsagePeriod();
      if (extConf != null) {
        privateKeyUsagePeriod = Validity.getInstance(extConf.getValidity());
      }
    }
  } // method initPrivateKeyUsagePeriod

  private void initPolicyConstraints(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.policyConstraints;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      PolicyConstraints extConf = getExtension(type, extensions).getPolicyConstraints();
      if (extConf != null) {
        this.policyConstraints = new ExtensionValue(critical(type), extConf.toXiPolicyConstraints());
      }
    }
  } // method initPolicyConstraints

  private void initPolicyMappings(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.policyMappings;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      PolicyMappings extConf = getExtension(type, extensions).getPolicyMappings();
      if (extConf != null) {
        this.policyMappings = new ExtensionValue(critical(type), extConf.toXiPolicyMappings());
      }
    }
  } // method initPolicyMappings

  private void initQcStatements(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.qCStatements;
    if (!extensionControls.containsKey(type)) {
      return;
    }

    extnIds.remove(type);
    QcStatements extConf = getExtension(type, extensions).getQcStatements();
    if (extConf == null) {
      return;
    }

    List<QcStatementType> qcStatementTypes = extConf.getQcStatements();
    this.qcStatementsOption = new ArrayList<>(qcStatementTypes.size());
    Set<String> currencyCodes = new HashSet<>();
    boolean requireInfoFromReq = false;

    for (QcStatementType m : qcStatementTypes) {
      ASN1ObjectIdentifier qcStatementId = new ASN1ObjectIdentifier(m.getStatementId().getOid());
      QcStatementOption qcStatementOption;

      QcStatementValueType statementValue = m.getStatementValue();
      if (statementValue == null) {
        qcStatementOption = new QcStatementOption(new QCStatement(qcStatementId));
      } else if (statementValue.getQcRetentionPeriod() != null) {
        QCStatement qcStatment = new QCStatement(qcStatementId, new ASN1Integer(statementValue.getQcRetentionPeriod()));
        qcStatementOption = new QcStatementOption(qcStatment);
      } else if (statementValue.getConstant() != null) {
        ASN1Encodable constantStatementValue;
        try {
          constantStatementValue = new ASN1StreamParser(statementValue.getConstant().getValue()).readObject();
        } catch (IOException ex) {
          throw new CertprofileException("can not parse the constant value of QcStatement");
        }
        qcStatementOption = new QcStatementOption(new QCStatement(qcStatementId, constantStatementValue));
      } else if (statementValue.getQcEuLimitValue() != null) {
        QcEuLimitValueType euLimitType = statementValue.getQcEuLimitValue();
        String tmpCurrency = euLimitType.getCurrency().toUpperCase();
        if (currencyCodes.contains(tmpCurrency)) {
          throw new CertprofileException("Duplicated definition of qcStatments with QCEuLimitValue"
              + " for the currency " + tmpCurrency);
        }

        Iso4217CurrencyCode currency = StringUtil.isNumber(tmpCurrency)
            ? new Iso4217CurrencyCode(Integer.parseInt(tmpCurrency)) : new Iso4217CurrencyCode(tmpCurrency);

        Range2Type r1 = euLimitType.getAmount();
        Range2Type r2 = euLimitType.getExponent();
        if (r1.getMin() == r1.getMax() && r2.getMin() == r2.getMax()) {
          MonetaryValue monetaryValue = new MonetaryValue(currency, r1.getMin(), r2.getMin());
          qcStatementOption = new QcStatementOption(new QCStatement(qcStatementId, monetaryValue));
        } else {
          qcStatementOption = new QcStatementOption(qcStatementId, new MonetaryValueOption(currency, r1, r2));
          requireInfoFromReq = true;
        }
        currencyCodes.add(tmpCurrency);
      } else if (statementValue.getPdsLocations() != null) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (PdsLocationType pl : statementValue.getPdsLocations()) {
          String lang = pl.getLanguage();
          if (lang.length() != 2) {
            throw new CertprofileException("invalid language '" + lang + "'");
          }

          vec.add(new DERSequence(new ASN1Encodable[]{new DERIA5String(pl.getUrl()), new DERPrintableString(lang)}));
        }
        qcStatementOption = new QcStatementOption(new QCStatement(qcStatementId, new DERSequence(vec)));
      } else {
        throw new CertprofileException("unknown value of qcStatment");
      }

      this.qcStatementsOption.add(qcStatementOption);
    } // end for

    if (requireInfoFromReq) {
      return;
    }

    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (QcStatementOption m : qcStatementsOption) {
      if (m.getStatement() == null) {
        throw new IllegalStateException("should not reach here");
      }
      vec.add(m.getStatement());
    }
    qcStatments = new ExtensionValue(critical(type), new DERSequence(vec));
    qcStatementsOption = null;
  } // method initQcStatements

  private void initSmimeCapabilities(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = Extn.id_smimeCapabilities;
    if (!extensionControls.containsKey(type)) {
      return;
    }
    extnIds.remove(type);

    SmimeCapabilities extConf = getExtension(type, extensions).getSmimeCapabilities();
    if (extConf == null) {
      return;
    }

    List<SmimeCapability> list = extConf.getCapabilities();

    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (SmimeCapability m : list) {
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getCapabilityId().getOid());
      ASN1Encodable params = null;
      SmimeCapabilityParameter capParams = m.getParameter();
      if (capParams != null) {
        if (capParams.getInteger() != null) {
          params = new ASN1Integer(capParams.getInteger());
        } else if (capParams.getBinary() != null) {
          params = readAsn1Encodable(capParams.getBinary().getValue());
        }
      }
      vec.add(new org.bouncycastle.asn1.smime.SMIMECapability(oid, params));
    }

    smimeCapabilities = new ExtensionValue(critical(type), new DERSequence(vec));
  } // method initSmimeCapabilities

  private void initSubjectAlternativeName(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.subjectAlternativeName;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      GeneralNameType extConf = getExtension(type, extensions).getSubjectAltName();
      if (extConf != null) {
        this.subjectAltNameModes = extConf.toGeneralNameModes();
      }
    }
  } // method initSubjectAlternativeName

  private void initSubjectInfoAccess(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.subjectInfoAccess;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      SubjectInfoAccess extConf = getExtension(type, extensions).getSubjectInfoAccess();
      if (extConf != null) {
        List<Access> list = extConf.getAccesses();
        this.subjectInfoAccessModes = new HashMap<>();
        for (Access entry : list) {
          this.subjectInfoAccessModes.put(new ASN1ObjectIdentifier(entry.getAccessMethod().getOid()),
              entry.getAccessLocation().toGeneralNameModes());
        }
      }
    }
  } // method initSubjectInfoAccess

  private void initTlsFeature(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = Extn.id_pe_tlsfeature;
    if (!extensionControls.containsKey(type)) {
      return;
    }
    extnIds.remove(type);
    TlsFeature extConf = getExtension(type, extensions).getTlsFeature();
    if (extConf == null) {
      return;
    }

    List<Integer> features = new ArrayList<>(extConf.getFeatures().size());
    for (DescribableInt m : extConf.getFeatures()) {
      int value = m.getValue();
      if (value < 0 || value > 65535) {
        throw new CertprofileException("invalid TLS feature (extensionType) " + value);
      }
      features.add(value);
    }
    Collections.sort(features);

    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (Integer m : features) {
      vec.add(new ASN1Integer(m));
    }
    tlsFeature = new ExtensionValue(critical(type), new DERSequence(vec));
  } // method initTlsFeature

  private void initSubjectDirAttrs(Set<ASN1ObjectIdentifier> extnIds, Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = Extension.subjectDirectoryAttributes;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      SubjectDirectoryAttributs extConf = getExtension(type, extensions).getSubjectDirectoryAttributs();
      if (extConf != null) {
        subjectDirAttrsControl = new SubjectDirectoryAttributesControl(toOidList(extConf.getTypes()));
      }
    }
  } // method initSubjectDirAttrs

  private static List<ASN1ObjectIdentifier> toOidList(List<DescribableOid> oidWithDescTypes) {
    if (CollectionUtil.isEmpty(oidWithDescTypes)) {
      return null;
    }

    List<ASN1ObjectIdentifier> oids = new LinkedList<>();
    for (DescribableOid type : oidWithDescTypes) {
      oids.add(new ASN1ObjectIdentifier(type.getOid()));
    }
    return Collections.unmodifiableList(oids);
  } // method toOidList

  GeneralNames createRequestedSubjectAltNames(
      X500Name requestedSubject, X500Name grantedSubject, Map<ASN1ObjectIdentifier, Extension> requestedExtensions)
      throws BadCertTemplateException {
    Extension extn = (requestedExtensions == null) ? null : requestedExtensions.get(Extension.subjectAlternativeName);
    ASN1Encodable extValue = (extn == null) ? null : extn.getParsedValue();

    if (extValue == null && subjectToSubjectAltNameModes == null) {
      return null;
    }

    GeneralNames reqNames = (extValue == null) ? null : GeneralNames.getInstance(extValue);
    if (subjectAltNameModes == null && subjectToSubjectAltNameModes == null) {
      return reqNames;
    }

    List<GeneralName> grantedNames = new LinkedList<>();
    // copy the required attributes of Subject
    if (subjectToSubjectAltNameModes != null) {
      for (Entry<ASN1ObjectIdentifier, GeneralNameTag> entry : subjectToSubjectAltNameModes.entrySet()) {
        ASN1ObjectIdentifier attrType = entry.getKey();
        GeneralNameTag tag = entry.getValue();

        RDN[] rdns = grantedSubject.getRDNs(attrType);
        if (rdns == null || rdns.length == 0) {
          rdns = requestedSubject.getRDNs(attrType);
        }

        if (rdns == null) {
          continue;
        }

        for (RDN rdn : rdns) {
          String rdnValue = X509Util.rdnValueToString(rdn.getFirst().getValue());
          GeneralName gn;
          switch (tag) {
            case rfc822Name:
            case IPAddress:
            case uniformResourceIdentifier:
            case DNSName:
            case directoryName:
            case registeredID:
              gn = new GeneralName(tag.getTag(), rdnValue);
              break;
            default:
              throw new IllegalStateException("unsupported GeneralName tag " + tag);
          } // end switch (tag)

          if (!grantedNames.contains(gn)) {
            grantedNames.add(gn);
          }
        }
      }
    }

    // copy the requested SubjectAltName entries
    if (reqNames != null) {
      GeneralName[] reqL = reqNames.getNames();
      for (GeneralName generalName : reqL) {
        GeneralName gn = BaseCertprofile.createGeneralName(generalName, subjectAltNameModes);
        if (!grantedNames.contains(gn)) {
          grantedNames.add(gn);
        }
      }
    }

    return grantedNames.isEmpty() ? null : new GeneralNames(grantedNames.toArray(new GeneralName[0]));
  } // method createRequestedSubjectAltNames

  public AuthorityInfoAccessControl getAiaControl() {
    return aiaControl;
  }

  public CrlDistributionPointsControl getCrlDpControl() {
    return crlDpControl;
  }

  public CrlDistributionPointsControl getFreshestCrlControl() {
    return freshestCrlControl;
  }

  public Map<ASN1ObjectIdentifier, GeneralNameTag> getSubjectToSubjectAltNameModes() {
    return subjectToSubjectAltNameModes;
  }

  public Set<GeneralNameMode> getSubjectAltNameModes() {
    return subjectAltNameModes;
  }

  public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> getSubjectInfoAccessModes() {
    return subjectInfoAccessModes;
  }

  public BiometricInfoOption getBiometricInfo() {
    return biometricInfo;
  }

  public org.bouncycastle.asn1.x509.CertificatePolicies getCertificatePolicies() {
    return certificatePolicies;
  }

  public Map<ASN1ObjectIdentifier, ExtensionValue> getConstantExtensions() {
    return constantExtensions;
  }

  public Set<ExtKeyUsageControl> getExtendedKeyusages() {
    return extendedKeyusages;
  }

  public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls() {
    return extensionControls;
  }

  public boolean isUseIssuerAndSerialInAki() {
    return useIssuerAndSerialInAki;
  }

  public SubjectKeyIdentifierControl getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public ExtensionValue getInhibitAnyPolicy() {
    return inhibitAnyPolicy;
  }

  public Set<KeyUsageControl> getKeyusages() {
    return keyusages;
  }

  public ExtensionValue getNameConstraints() {
    return nameConstraints;
  }

  public Integer getPathLen() {
    return pathLen;
  }

  public ExtensionValue getPolicyConstraints() {
    return policyConstraints;
  }

  public ExtensionValue getPolicyMappings() {
    return policyMappings;
  }

  public Validity getPrivateKeyUsagePeriod() {
    return privateKeyUsagePeriod;
  }

  public ExtensionValue getQcStatments() {
    return qcStatments;
  }

  public List<QcStatementOption> getQcStatementsOption() {
    return qcStatementsOption;
  }

  public ExtensionValue getSmimeCapabilities() {
    return smimeCapabilities;
  }

  public ExtensionValue getTlsFeature() {
    return tlsFeature;
  }

  public SubjectDirectoryAttributesControl getSubjectDirAttrsControl() {
    return subjectDirAttrsControl;
  }

  private static ExtensionType getExtension(
      ASN1ObjectIdentifier type, Map<String, ExtensionType> extensions) {
    return Optional.ofNullable(extensions.get(type.getId())).orElseThrow(() ->
        new IllegalStateException("should not reach here: undefined extension "
          + ObjectIdentifiers.oidToDisplayName(type)));
  } // method getExtension

  private static ASN1Encodable readAsn1Encodable(byte[] encoded) throws CertprofileException {
    ASN1StreamParser parser = new ASN1StreamParser(encoded);
    try {
      return parser.readObject();
    } catch (IOException ex) {
      throw new CertprofileException("could not parse the constant extension value", ex);
    }
  } // method readAsn1Encodable

  private boolean critical(ASN1ObjectIdentifier type) {
    return extensionControls.get(type).isCritical();
  }

}
