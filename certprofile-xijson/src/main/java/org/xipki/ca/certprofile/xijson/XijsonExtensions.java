// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.util.Pack;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ProfileUtil;
import org.xipki.ca.api.profile.ctrl.AuthorityInfoAccessControl;
import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.ctrl.ExtensionsControl;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.api.profile.ctrl.SubjectControl;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.ca.api.profile.id.QCStatementID;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.ca.certprofile.xijson.conf.RdnType;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.ca.certprofile.xijson.conf.extn.*;
import org.xipki.ca.certprofile.xijson.conf.extn.SmimeCapabilities.SmimeCapability;
import org.xipki.ca.certprofile.xijson.conf.extn.SubjectInfoAccess.Access;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.SubjectKeyIdentifierControl;
import org.xipki.util.extra.type.TripleState;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

/**
 * Extensions configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class XijsonExtensions {

  private final boolean keepOrder;

  private final List<ASN1ObjectIdentifier> extensionIDs;

  private AuthorityInfoAccessControl aiaControl;

  private Map<ASN1ObjectIdentifier, GeneralNameTag>
      subjectToSubjectAltNameModes;

  private Set<GeneralNameTag> subjectAltNameModes;

  private Map<ASN1ObjectIdentifier, Set<GeneralNameTag>> subjectInfoAccessModes;

  private BiometricInfo biometricInfo;

  private CertificatePolicies certificatePolicies;

  private final Map<ASN1ObjectIdentifier, ExtensionValue> constantExtensions;

  private Set<ExtKeyUsageControl> extendedKeyusages;

  private final ExtensionsControl extensionsControl;

  private SubjectKeyIdentifierControl subjectKeyIdentifier;

  private ExtensionValue inhibitAnyPolicy;

  private KeyUsageControl keyUsage;

  private ExtensionValue nameConstraints;

  private Integer pathLen;

  private ExtensionValue policyConstraints;

  private ExtensionValue policyMappings;

  private Validity privateKeyUsagePeriod;

  private ExtensionValue qcStatements;

  private List<QcStatementOption> qcStatementsOption;

  private ExtensionValue smimeCapabilities;

  private ExtensionValue tlsFeature;

  private ASN1ObjectIdentifier cccExtensionSchemaType;

  private ExtensionValue cccExtensionSchemaValue;

  XijsonExtensions(XijsonCertprofileType conf, SubjectControl subjectControl)
      throws CertprofileException {
    Args.notNull(subjectControl, "subjectControl");

    Boolean b = conf.getKeepExtensionsOrder();
    this.keepOrder = b != null && b;

    List<ExtensionType> extensionsConf = conf.getExtensions();
    List<ASN1ObjectIdentifier> extensionIDs =
        new ArrayList<>(extensionsConf.size());
    for (ExtensionType t : extensionsConf) {
      extensionIDs.add(t.getType().getOid());
    }
    this.extensionIDs = Collections.unmodifiableList(extensionIDs);

    // Extensions
    Map<String, ExtensionType> extensions =
        Args.notNull(conf, "conf").buildExtensions();

    // Extension controls
    this.extensionsControl = conf.buildExtensionControls();

    // get a copy of extensions IDs
    Set<ASN1ObjectIdentifier> extnIds = new HashSet<>(this.extensionIDs);

    // AuthorityInfoAccess
    initAuthorityInfoAccess(extnIds, extensions);

    // AuthorityKeyIdentifier
    initAuthorityKeyIdentifier(extnIds);

    // SubjectKeyIdentifier
    initSubjectKeyIdentifier(extnIds, extensions);

    // BasicConstraints
    initBasicConstraints(extnIds, extensions);

    // Certificate Policies
    initCertificatePolicies(extnIds, extensions);

    // BiometricInfo
    initBiometricInfo(extnIds, extensions);

    // ExtendedKeyUsage
    initExtendedKeyUsage(extnIds, extensions);

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

    initSubjectToSubjectAltNames(conf.getSubject());

    // SubjectInfoAccess
    initSubjectInfoAccess(extnIds, extensions);

    // TlsFeature
    initTlsFeature(extnIds, extensions);

    // CCC
    initCCCExtensionSchemas(extnIds, extensions);

    // constant extensions
    this.constantExtensions = conf.buildConstantExtensions();
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
     * Make sure that if email address is contained in subject, it must be
     * duplicated in the SubjectAltName extension as rfc822Name.
     */
    if (subjectControl.getControl(OIDs.DN.emailAddress) != null) {
      ASN1ObjectIdentifier type = OIDs.Extn.subjectAlternativeName;
      if (!extensionsControl.containsID(type)) {
        throw new CertprofileException(
            "attribute emailAddress cannot be configured if extension" +
            " subjectAltNames is not permitted");
      }

      if (subjectAltNameModes != null) {
        if (!subjectAltNameModes.contains(GeneralNameTag.rfc822Name)) {
          throw new CertprofileException("attribute emailAddress cannot be " +
              "configured if extension subjectAltNames with rfc822Name is " +
              "not permitted");
        }
      }
    }

    // Remove the extension processed not by the Certprofile, but by the CA
    Arrays.asList(
        OIDs.Extn.issuerAlternativeName,
        OIDs.Extn.authorityInfoAccess,
        OIDs.Extn.cRLDistributionPoints,
        OIDs.Extn.freshestCRL,
        OIDs.Extn.subjectKeyIdentifier,
        OIDs.Extn.subjectInfoAccess,
        OIDs.Extn.id_pkix_ocsp_nocheck,
        OIDs.Extn.id_SignedCertificateTimestampList)
        .forEach(extnIds::remove);

    Set<ASN1ObjectIdentifier> copyOfExtnIds = new HashSet<>(extnIds);

    // extensions that will just use the requested value
    if (!extnIds.isEmpty()) {
      for (ASN1ObjectIdentifier extnId : copyOfExtnIds) {
        ExtensionType type = extensions.get(extnId.getId());
        TripleState state = type.getInRequest();
        if (state == TripleState.required) {
          extnIds.remove(extnId);
        }
      }
    }

    if (!extnIds.isEmpty()) {
      throw new CertprofileException(
          "Cannot process the extensions: " + extnIds);
    }
  } // method initialize0

  private void initAuthorityInfoAccess(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.authorityInfoAccess;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    AuthorityInfoAccess extConf =
        getExtension(type, extensions).getAuthorityInfoAccess();
    this.aiaControl = (extConf == null)
        ? new AuthorityInfoAccessControl(false, true)
        : new AuthorityInfoAccessControl(extConf.isIncludeCaIssuers(),
              extConf.isIncludeOcsp());
  }

  private void initAuthorityKeyIdentifier(Set<ASN1ObjectIdentifier> extnIds) {
    ASN1ObjectIdentifier type = OIDs.Extn.authorityKeyIdentifier;
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
    }
  }

  private void initSubjectKeyIdentifier(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.subjectKeyIdentifier;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    this.subjectKeyIdentifier =
        getExtension(type, extensions).getSubjectKeyIdentifier();

    if (subjectKeyIdentifier == null) {
      subjectKeyIdentifier = new SubjectKeyIdentifierControl();
    }
  }

  private void initBasicConstraints(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.basicConstraints;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    BasicConstraints extConf =
        getExtension(type, extensions).getBasicConstraints();
    if (extConf == null) {
      extConf = getExtension(type, extensions).getBasicConstraints();
    }

    if (extConf != null) {
      this.pathLen = extConf.getPathLen();
    }
  }

  private void initBiometricInfo(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.biometricInfo;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);

    this.biometricInfo = getExtension(type, extensions).getBiometricInfo();
  }

  private void initCertificatePolicies(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.certificatePolicies;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    org.xipki.ca.certprofile.xijson.conf.extn.CertificatePolicies extConf
        = getExtension(type, extensions).getCertificatePolicies();
    if (extConf == null) {
      return;
    }

    certificatePolicies = extConf.toCertificatePolicies();
  }

  private void initExtendedKeyUsage(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.extendedKeyUsage;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtendedKeyUsage extConf = getExtension(type, extensions)
        .getExtendedKeyUsage();
    if (extConf != null) {
      this.extendedKeyusages = extConf.toXiExtKeyUsageOptions();
    }
  }

  private void initInhibitAnyPolicy(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = OIDs.Extn.inhibitAnyPolicy;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    InhibitAnyPolicy extConf = getExtension(type, extensions)
        .getInhibitAnyPolicy();
    if (extConf == null) {
      return;
    }

    int skipCerts = extConf.getSkipCerts();
    if (skipCerts < 0) {
      throw new CertprofileException(
          "negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
    }

    boolean critical = critical(type);
    this.inhibitAnyPolicy = new ExtensionValue(critical,
        new ASN1Integer(BigInteger.valueOf(skipCerts)));
  }

  private void initKeyUsage(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.keyUsage;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    KeyUsage extConf = getExtension(type, extensions).getKeyUsage();
    if (extConf != null) {
      this.keyUsage = extConf.toXiKeyUsageOptions();
    }
  }

  private void initNameConstraints(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.nameConstraints;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    NameConstraints extConf = getExtension(type, extensions)
        .getNameConstraints();
    if (extConf == null) {
      return;
    }

    boolean critical = critical(type);
    this.nameConstraints = new ExtensionValue(critical,
        extConf.toNameConstraints());
  }

  private void initPolicyConstraints(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = OIDs.Extn.policyConstraints;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    PolicyConstraints extConf = getExtension(type, extensions)
        .getPolicyConstraints();
    if (extConf == null) {
      return;
    }

    Integer require = extConf.getRequireExplicitPolicy();
    if (require != null && require < 0) {
      throw new CertprofileException(
          "negative requireExplicitPolicy is not allowed: " + require);
    }

    Integer inhibit = extConf.getInhibitPolicyMapping();
    if (inhibit != null && inhibit < 0) {
      throw new CertprofileException(
          "negative inhibitPolicyMapping is not allowed: " + inhibit);
    }

    if (require == null && inhibit == null) {
      return;
    }

    BigInteger requireBn = require == null ? null : BigInteger.valueOf(require);
    BigInteger inhibitBn = inhibit == null ? null : BigInteger.valueOf(inhibit);

    boolean critical = critical(type);
    this.policyConstraints = new ExtensionValue(critical,
        new org.bouncycastle.asn1.x509.PolicyConstraints(requireBn, inhibitBn));
  } // method initPolicyConstraints

  private void initPrivateKeyUsagePeriod(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.privateKeyUsagePeriod;
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
      PrivateKeyUsagePeriod extConf =
          getExtension(type, extensions).getPrivateKeyUsagePeriod();
      if (extConf != null) {
        privateKeyUsagePeriod = Validity.getInstance(extConf.getValidity());
      }
    }
  }

  private void initPolicyMappings(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.policyMappings;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    PolicyMappings extConf = getExtension(type, extensions).getPolicyMappings();
    if (extConf == null) {
      return;
    }

    boolean critical = critical(type);
    this.policyMappings = new ExtensionValue(critical,
        extConf.toPolicyMappings());
  }

  private void initQcStatements(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions)
      throws CertprofileException {
    ASN1ObjectIdentifier type = OIDs.Extn.qCStatements;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    QcStatements extConf = getExtension(type, extensions).getQcStatements();
    if (extConf == null) {
      return;
    }

    List<QcStatements.QcStatementType> qcStatementTypes =
        extConf.getQcStatements();
    this.qcStatementsOption = new ArrayList<>(qcStatementTypes.size());
    Set<String> currencyCodes = new HashSet<>();
    boolean requireInfoFromReq = false;

    for (QcStatements.QcStatementType m : qcStatementTypes) {
      QCStatementID qcStatementId = m.getStatementId();

      QcStatements.QcStatementValueType statementValue = m.getStatementValue();
      QcStatementOption qcStatementOption;
      if (statementValue == null) {
        qcStatementOption = new QcStatementOption(
            new QCStatement(qcStatementId.getOid()));
      } else if (statementValue.getQcRetentionPeriod() != null) {
        QCStatement qcStatement = new QCStatement(qcStatementId.getOid(),
            new ASN1Integer(statementValue.getQcRetentionPeriod()));
        qcStatementOption = new QcStatementOption(qcStatement);
      } else if (statementValue.getConstant() != null) {
        ASN1Encodable constantStatementValue;
        try {
          constantStatementValue = statementValue.getConstant().toASN1();
        } catch (IOException ex) {
          throw new CertprofileException(
              "can not parse the constant value of QcStatement");
        }
        qcStatementOption = new QcStatementOption(
            new QCStatement(qcStatementId.getOid(), constantStatementValue));
      } else if (statementValue.getQcEuLimitValue() != null) {
        QcStatements.QcEuLimitValueType euLimitType =
            statementValue.getQcEuLimitValue();
        String tmpCurrency = euLimitType.getCurrency().toUpperCase();
        if (currencyCodes.contains(tmpCurrency)) {
          throw new CertprofileException(
              "Duplicated definition of qcStatements with " +
              "QCEuLimitValue for the currency " + tmpCurrency);
        }

        Iso4217CurrencyCode currency = StringUtil.isNumber(tmpCurrency)
            ? new Iso4217CurrencyCode(Integer.parseInt(tmpCurrency))
            : new Iso4217CurrencyCode(tmpCurrency);

        QcStatements.Range2Type r1 = euLimitType.getAmount();
        QcStatements.Range2Type r2 = euLimitType.getExponent();
        if (r1.getMin() == r1.getMax() && r2.getMin() == r2.getMax()) {
          MonetaryValue monetaryValue =
              new MonetaryValue(currency, r1.getMin(), r2.getMin());
          qcStatementOption = new QcStatementOption(
              new QCStatement(qcStatementId.getOid(), monetaryValue));
        } else {
          qcStatementOption = new QcStatementOption(qcStatementId.getOid(),
              new MonetaryValueOption(currency, r1, r2));
          requireInfoFromReq = true;
        }
        currencyCodes.add(tmpCurrency);
      } else if (statementValue.getPdsLocations() != null) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (QcStatements.PdsLocationType pl
            : statementValue.getPdsLocations()) {
          String lang = pl.getLanguage();
          if (lang.length() != 2) {
            throw new CertprofileException("invalid language '" + lang + "'");
          }

          vec.add(new DERSequence(new ASN1Encodable[]{
              new DERIA5String(pl.getUrl()), new DERPrintableString(lang)}));
        }
        qcStatementOption = new QcStatementOption(new QCStatement(
            qcStatementId.getOid(), new DERSequence(vec)));
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
    qcStatements = new ExtensionValue(critical(type), new DERSequence(vec));
    qcStatementsOption = null;
  } // method initQcStatements

  private void initSmimeCapabilities(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.id_smimeCapabilities;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);

    SmimeCapabilities extConf =
        getExtension(type, extensions).getSmimeCapabilities();
    if (extConf == null) {
      return;
    }

    List<SmimeCapability> list = extConf.getCapabilities();

    boolean critical = critical(type);
    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (SmimeCapability m : list) {
      ASN1ObjectIdentifier oid = m.getCapabilityId();
      ASN1Encodable params = null;
      Integer capParams = m.getParameter();
      if (capParams != null) {
        params = new ASN1Integer(capParams);
      }
      vec.add(new org.bouncycastle.asn1.smime.SMIMECapability(oid, params));
    }

    smimeCapabilities = new ExtensionValue(critical, new DERSequence(vec));
  } // method initSmimeCapabilities

  private void initSubjectAlternativeName(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.subjectAlternativeName;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    GeneralNameType extConf = getExtension(type, extensions)
        .getSubjectAltName();
    if (extConf != null) {
      this.subjectAltNameModes = extConf.getModes();
    }
  } // method initSubjectAlternativeName

  private void initSubjectToSubjectAltNames(List<RdnType> list)
      throws CertprofileException {
    if (CollectionUtil.isEmpty(list)) {
      return;
    }

    subjectToSubjectAltNameModes = new HashMap<>();
    for (RdnType m : list) {
      GeneralNameTag targetTag = m.getToSAN();
      /*
       * RFC 5280, Section 4.1.2.7 Subject
       *    Conforming implementations generating new certificates with
       *    electronic mail addresses MUST use the rfc822Name in the subject
       *    alternative name extension (Section 4.2.1.6) to describe such
       *    identities.  Simultaneous inclusion of the emailAddress attribute
       *    in the subject distinguished name to support legacy implementations
       *    is deprecated but permitted.
       *
       * Make sure that if email address is contained in subject, it must be
       * duplicated in the SubjectAltName extension as rfc822Name.
       */
      if (m.getType() == AttributeType.emailAddress) {
        // we allow targetTag to be null to generate legacy certificates.
        if (targetTag != null && targetTag != GeneralNameTag.rfc822Name) {
          throw new CertprofileException("toSAN != rfc822Name: " + targetTag);
        }
      }

      if (targetTag == null) {
        continue;
      }

      if (!subjectAltNameModes.contains(targetTag)) {
        throw new CertprofileException("target tag " + targetTag +
            " not allowed in SAN");
      }

      switch (targetTag) {
        case rfc822Name:
        case DNSName:
        case uri:
        case IPAddress:
        case directoryName:
        case registeredID:
          break;
        default:
          throw new CertprofileException("unsupported toSAN tag " + targetTag);
      }

      subjectToSubjectAltNameModes.put(m.getType().getOid(), targetTag);
    }
  } // method initSubjectToSubjectAltNames

  private void initSubjectInfoAccess(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.subjectInfoAccess;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    SubjectInfoAccess extConf = getExtension(type, extensions)
        .getSubjectInfoAccess();
    if (extConf == null) {
      return;
    }

    List<Access> list = extConf.getAccesses();
    this.subjectInfoAccessModes = new HashMap<>();
    for (Access entry : list) {
      this.subjectInfoAccessModes.put(entry.getAccessMethod().getOid(),
          entry.getAccessLocation().getModes());
    }
  } // method initSubjectInfoAccess

  private void initTlsFeature(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) {
    ASN1ObjectIdentifier type = OIDs.Extn.id_pe_tlsfeature;
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    TlsFeature extConf = getExtension(type, extensions).getTlsFeature();
    if (extConf == null) {
      return;
    }

    List<Integer> features = new ArrayList<>(extConf.getFeatures().size());
    features.addAll(extConf.getFeatures());
    Collections.sort(features);

    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (Integer m : features) {
      vec.add(new ASN1Integer(m));
    }
    boolean critical = critical(type);
    tlsFeature = new ExtensionValue(critical, new DERSequence(vec));
  }

  private void initCCCExtensionSchemas(
      Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = null;
    for (ASN1ObjectIdentifier m : extnIds) {
      if (m.on(OIDs.Extn.id_ccc_extn)) {
        if (type != null) {
          throw new CertprofileException("Maximal one CCC Extension is " +
              "allowed, but configured at least 2.");
        }
        type = m;
      }
    }

    if (type == null) {
      return;
    }

    extnIds.remove(type);
    ExtensionType ex = extensions.get(type.getId());
    if (!ex.isCritical()) {
      throw new CertprofileException("CCC Extension must be set to " +
          "critical, but configured non-critical.");
    }

    List<ASN1ObjectIdentifier> simpleSchemaTypes = Arrays.asList(
        OIDs.Extn.id_ccc_K_Vehicle_Cert,
        OIDs.Extn.id_ccc_F_External_CA_Cert,
        OIDs.Extn.id_ccc_P_VehicleOEM_Enc_Cert,
        OIDs.Extn.id_ccc_Q_VehicleOEM_Sig_Cert,
        OIDs.Extn.id_ccc_Device_Enc_Cert,
        OIDs.Extn.id_ccc_Vehicle_Intermediate_Cert,
        OIDs.Extn.id_ccc_J_VehicleOEM_CA_Cert,
        OIDs.Extn.id_ccc_M_VehicleOEM_CA_Cert);

    boolean isInstanceCAExtensionSchema =
        OIDs.Extn.id_ccc_E_Instance_CA_Cert.equals(type);
    if (!isInstanceCAExtensionSchema && !simpleSchemaTypes.contains(type)) {
      return;
    }

    CCCSimpleExtensionSchema schema = isInstanceCAExtensionSchema
        ? ex.getCccInstanceCAExtensionSchema() : ex.getCccExtensionSchema();

    if (schema == null) {
      throw new CertprofileException(
          (isInstanceCAExtensionSchema ? "cccInstanceCAExtensionSchema"
              : "ccExtensionSchema") +
          " is not set for " + type);
    }

    this.cccExtensionSchemaType = type;

    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1Integer(schema.getVersion()));
    if (isInstanceCAExtensionSchema) {
      CCCInstanceCAExtensionSchema schema1 =
          (CCCInstanceCAExtensionSchema) schema;

      byte[] bytes = Pack.longToBigEndian(schema1.getAppletVersion());
      vec.add(new DEROctetString(Arrays.copyOfRange(bytes, 4, 8)));
      if (schema1.getPlatformInformation() != null) {
        vec.add(new DEROctetString(schema1.getPlatformInformation()));
      }
    }

    this.cccExtensionSchemaValue =
        new ExtensionValue(ex.isCritical(), new DERSequence(vec));
  }

  public static GeneralNames createRequestedSubjectAltNames(
      X500Name reqSubject, GeneralNames sanExtnValue,
      Set<GeneralNameTag> subjectAltNameModes,
      Map<ASN1ObjectIdentifier, GeneralNameTag> subjectToSubjectAltNameModes)
      throws BadCertTemplateException {
    List<GeneralName> list = new LinkedList<>();

    if (sanExtnValue != null) {
      for (GeneralName generalName : sanExtnValue.getNames()) {
        list.add(ProfileUtil.createGeneralName(
                  generalName, subjectAltNameModes));
      }
    }

    if (subjectToSubjectAltNameModes != null) {
      for (ASN1ObjectIdentifier attrType
          : subjectToSubjectAltNameModes.keySet()) {
        GeneralNameTag targetTag = subjectToSubjectAltNameModes.get(attrType);

        RDN[] rdns = reqSubject.getRDNs(attrType);
        if (rdns == null) {
          continue;
        }

        for (RDN rdn : rdns) {
          String text = X509Util.rdnValueToString(rdn.getFirst().getValue());
          if (subjectAltNameModes == null
              || subjectAltNameModes.contains(targetTag)) {
            list.add(new GeneralName(targetTag.getTag(), text));
          }
        }
      }
    }

    return list.isEmpty() ? null
        : new GeneralNames(list.toArray(new GeneralName[0]));
  }

  public AuthorityInfoAccessControl getAiaControl() {
    return aiaControl;
  }

  public BiometricInfo getBiometricInfo() {
    return biometricInfo;
  }

  public Validity getPrivateKeyUsagePeriod() {
    return privateKeyUsagePeriod;
  }

  public ExtensionValue getQcStatements() {
    return qcStatements;
  }

  List<QcStatementOption> getQcStatementsOption() {
    return qcStatementsOption;
  }

  public Set<GeneralNameTag> getSubjectAltNameModes() {
    return subjectAltNameModes;
  }

  public Map<ASN1ObjectIdentifier, GeneralNameTag>
      getSubjectToSubjectAltNameModes() {
    return subjectToSubjectAltNameModes;
  }

  public Map<ASN1ObjectIdentifier, Set<GeneralNameTag>>
      getSubjectInfoAccessModes() {
    return subjectInfoAccessModes;
  }

  public CertificatePolicies getCertificatePolicies() {
    return certificatePolicies;
  }

  public Map<ASN1ObjectIdentifier, ExtensionValue> getConstantExtensions() {
    return constantExtensions;
  }

  public Set<ExtKeyUsageControl> getExtendedKeyusages() {
    return extendedKeyusages;
  }

  public ExtensionsControl getExtensionControls() {
    return extensionsControl;
  }

  public SubjectKeyIdentifierControl getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public ExtensionValue getInhibitAnyPolicy() {
    return inhibitAnyPolicy;
  }

  public Set<KeySingleUsage> getKeyUsage(KeySpec keySpec) {
    return keyUsage == null ? null : keyUsage.getUsages(keySpec);
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

  public ExtensionValue getSmimeCapabilities() {
    return smimeCapabilities;
  }

  public ExtensionValue getTlsFeature() {
    return tlsFeature;
  }

  public ASN1ObjectIdentifier getCccExtensionSchemaType() {
    return cccExtensionSchemaType;
  }

  public ExtensionValue getCccExtensionSchemaValue() {
    return cccExtensionSchemaValue;
  }

  public boolean isKeepOrder() {
    return keepOrder;
  }

  public List<ASN1ObjectIdentifier> getExtensionIDs() {
    return extensionIDs;
  }

  private static ExtensionType getExtension(
      ASN1ObjectIdentifier type, Map<String, ExtensionType> extensions) {
    return Optional.ofNullable(extensions.get(type.getId())).orElseThrow(() ->
        new IllegalStateException("should not reach here: undefined extension "
          + OIDs.oidToDisplayName(type)));
  }

  private boolean critical(ASN1ObjectIdentifier type) {
    return extensionsControl.getControl(type).isCritical();
  }

}
