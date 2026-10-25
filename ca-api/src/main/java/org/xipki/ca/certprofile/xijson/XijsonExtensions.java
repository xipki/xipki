// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.pkix.asn1.ccc.SimpleExtensionSchema;
import org.xipki.pkix.asn1.cert.DocumentTypeListSyntax;
import org.xipki.pkix.asn1.cert.TLSFeatures;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.OIDs;
import org.xipki.codec.asn1.oid.SpdmOIDs;
import org.xipki.pkix.asn1.smime.SMIMECapabilities;
import org.xipki.pkix.asn1.smime.SMIMECapability;
import org.xipki.pkix.asn1.spdm.SpdmCertOid;
import org.xipki.pkix.asn1.spdm.SpdmCertOids;
import org.xipki.pkix.asn1.stir.JWTClaimConstraints;
import org.xipki.pkix.asn1.stir.JWTClaimNames;
import org.xipki.pkix.asn1.stir.JWTClaimPermittedValues;
import org.xipki.pkix.asn1.stir.JWTClaimPermittedValuesList;
import org.xipki.pkix.asn1.x500.RDN;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.CertificatePolicies;
import org.xipki.pkix.asn1.x509.GeneralName;
import org.xipki.pkix.asn1.x509.GeneralNames;
import org.xipki.pkix.asn1.x509.PolicyConstraints;
import org.xipki.pkix.asn1.x509.qualified.Iso4217CurrencyCode;
import org.xipki.pkix.asn1.x509.qualified.MonetaryValue;
import org.xipki.pkix.asn1.x509.qualified.PdsLocation;
import org.xipki.pkix.asn1.x509.qualified.PdsLocations;
import org.xipki.pkix.asn1.x509.qualified.QCStatement;
import org.xipki.pkix.asn1.x509.qualified.QCStatements;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ProfileUtil;
import org.xipki.ca.api.profile.ctrl.AuthorityInfoAccessControl;
import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.ctrl.ExtensionsControl;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.api.profile.ctrl.SubjectControl;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.api.profile.id.OtherNameID;
import org.xipki.ca.api.profile.id.QCStatementID;
import org.xipki.ca.api.profile.id.SubjectDirectoryAttributeType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionValueConf;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.ca.certprofile.xijson.conf.RdnType;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.exception.BadCertTemplateException;
import org.xipki.pkix.util.X509Util;
import org.xipki.ca.api.CertprofileException;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.ca.api.SubjectKeyIdentifierControl;
import org.xipki.ca.api.TripleState;
import org.xipki.pkix.util.conf.Validity;
import org.xipki.pkix.util.misc.StringUtil;

import java.math.BigInteger;
import java.util.*;

/**
 * Xijson Extensions.
 *
 * @author Lijun Liao (xipki)
 */
public class XijsonExtensions {

  private final List<Asn1Oid> extensionIDs;

  private AuthorityInfoAccessControl aiaControl;

  private Map<Asn1Oid, GeneralNameTag> subjectToSubjectAltNameModes;

  private Set<GeneralNameTag> subjectAltNameModes;

  private Set<Asn1Oid> subjectAltNameOtherNameTypes;

  private Map<Asn1Oid, Set<GeneralNameTag>> subjectInfoAccessModes;

  private ExtensionValueConf.BiometricInfo biometricInfo;

  private CertificatePolicies certificatePolicies;

  private final Map<Asn1Oid, ExtensionValue> constantExtensions;

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

  private List<Asn1Oid> subjectDirectoryAttributes;

  private Asn1Oid cccExtensionSchemaType;

  private ExtensionValue cccSimpleExtensionSchemaValue;

  private ExtensionValue microsoftCertTemplateName;

  private ExtensionValue microsoftCertTemplateInformation;

  private ExtensionValueConf.MicrosoftSID microsoftSID;

  private ExtensionValue spdmCertOids;

  private ExtensionValue stirJWTClaimPermittedValues;

  private ExtensionValue masaUrl;

  private ExtensionValue mrtdDocumentTypes;

  XijsonExtensions(XijsonCertprofileType conf, SubjectControl subjectControl)
      throws CertprofileException {
    Args.notNull(subjectControl, "subjectControl");

    List<ExtensionType> extensionsConf = conf.extensions();
    List<Asn1Oid> extensionIDs = new ArrayList<>(extensionsConf.size());
    for (ExtensionType t : extensionsConf) {
      extensionIDs.add(t.type().oid());
    }
    this.extensionIDs = Collections.unmodifiableList(extensionIDs);

    // Extensions
    Map<String, ExtensionType> extensions = Args.notNull(conf, "conf").buildExtensions();

    // Extension controls
    this.extensionsControl = conf.buildExtensionControls();

    // get a copy of extensions IDs
    Set<Asn1Oid> extnIds = new HashSet<>(this.extensionIDs);

    // AuthorityInfoAccess
    initAuthorityInfoAccess(extnIds, extensions);

    // AuthorityKeyIdentifier
    initAuthorityKeyIdentifier(extnIds);

    // SubjectKeyIdentifier
    initSubjectKeyIdentifier(extnIds, extensions);

    // BasicConstraints
    initBasicConstraints(extnIds, extensions);

    // Certificate Policies
    try {
      initCertificatePolicies(extnIds, extensions);
    } catch (CodecException e) {
      throw new CertprofileException("could not initialize extension CertificatePolicies", e);
    }

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
    try {
      initQcStatements(extnIds, extensions);
    } catch (CodecException e) {
      throw new CertprofileException("could not initialize extension QCStatements", e);
    }

    // SMIMECapabilities
    initSmimeCapabilities(extnIds, extensions);

    // SubjectAltNameMode
    initSubjectAlternativeName(extnIds, extensions);

    initSubjectToSubjectAltNames(conf.subject());

    // SubjectInfoAccess
    initSubjectInfoAccess(extnIds, extensions);

    // SubjectDirectoryAttributes
    initSubjectDirectoryAttributeTypes(extnIds, extensions);

    // TlsFeature
    initTlsFeature(extnIds, extensions);

    // CCC
    initCCCExtensionSchemas(extnIds, extensions);

    // Microsoft
    initMicrosoftExtensions(extnIds, extensions);

    // SPDM
    initSpdmExtensions(extnIds, extensions);

    // STIR
    initStirExtensions(extnIds, extensions);

    // RFC8226
    initRfc8226Extensions(extnIds, extensions);

    // BRSKI
    initBrskiExtensions(extnIds, extensions);

    // ICAO MRTD
    initMrtdExtensions(extnIds, extensions);

    // DICE
    initDiceExtensions(extnIds, extensions);

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
    if (subjectControl.getControl(AttributeOIDs.emailAddress) != null) {
      Asn1Oid type = ExtensionOIDs.subjectAlternativeName;
      if (!extensionsControl.containsID(type)) {
        throw new CertprofileException("attribute emailAddress cannot be configured if extension" +
            " subjectAltNames is not permitted");
      }

      if (subjectAltNameModes != null) {
        if (!subjectAltNameModes.contains(GeneralNameTag.rfc822Name)) {
          throw new CertprofileException("attribute emailAddress cannot be " +
              "configured if extension subjectAltNames with rfc822Name is not permitted");
        }
      }
    }

    // Remove the extension processed not by the Certprofile, but by the CA
    Arrays.asList(
            ExtensionID.issuerAltName.oid(),
            ExtensionID.authorityInfoAccess.oid(),
            ExtensionID.crlDistributionPoints.oid(),
            ExtensionID.freshestCRL.oid(),
            ExtensionID.subjectKeyIdentifier.oid(),
            ExtensionID.subjectInfoAccess.oid(),
            ExtensionID.ocspNoCheck.oid(),
            ExtensionID.signedCertificateTimestampList.oid())
        .forEach(extnIds::remove);

    Set<Asn1Oid> copyOfExtnIds = new HashSet<>(extnIds);

    // extensions that will just use the requested value
    if (!extnIds.isEmpty()) {
      for (Asn1Oid extnId : copyOfExtnIds) {
        ExtensionType type = extensions.get(extnId.getId());
        TripleState state = type.inRequest();
        if (state == TripleState.required) {
          extnIds.remove(extnId);
        }
      }
    }

    if (!extnIds.isEmpty()) {
      throw new CertprofileException("Cannot process the extensions: " + extnIds);
    }
  } // method initialize0

  private void initAuthorityInfoAccess(Set<Asn1Oid> extnIds,
                                      Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.authorityInfoAccess.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.AuthorityInfoAccess extConf =
        getExtension(type, extensions).authorityInfoAccess();
    this.aiaControl = (extConf == null)
        ? new AuthorityInfoAccessControl(false, true)
        : new AuthorityInfoAccessControl(extConf.isIncludeCaIssuers(), extConf.isIncludeOcsp());
  }

  private void initAuthorityKeyIdentifier(Set<Asn1Oid> extnIds) {
    Asn1Oid type = ExtensionID.authorityKeyIdentifier.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
    }
  }

  private void initSubjectKeyIdentifier(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.subjectKeyIdentifier.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    this.subjectKeyIdentifier = getExtension(type, extensions).subjectKeyIdentifier();

    if (subjectKeyIdentifier == null) {
      subjectKeyIdentifier = new SubjectKeyIdentifierControl();
    }
  }

  private void initBasicConstraints(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.basicConstraints.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.BasicConstraints extConf = getExtension(type, extensions).basicConstraints();
    if (extConf == null) {
      extConf = getExtension(type, extensions).basicConstraints();
    }

    if (extConf != null) {
      this.pathLen = extConf.pathLen();
    }
  }

  private void initBiometricInfo(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.biometricInfo.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    this.biometricInfo = getExtension(type, extensions).biometricInfo();
  }

  private void initCertificatePolicies(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) throws CodecException {
    Asn1Oid type = ExtensionID.certificatePolicies.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.CertificatePolicies extConf
        = getExtension(type, extensions).certificatePolicies();
    if (extConf == null) {
      return;
    }

    certificatePolicies = extConf.toCertificatePolicies();
  }

  private void initExtendedKeyUsage(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.extendedKeyUsage.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.ExtendedKeyUsage extConf = getExtension(type, extensions).extendedKeyUsage();
    if (extConf != null) {
      this.extendedKeyusages = extConf.toXiExtKeyUsageOptions();
    }
  }

  private void initInhibitAnyPolicy(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    Asn1Oid type = ExtensionID.inhibitAnyPolicy.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.InhibitAnyPolicy extConf = getExtension(type, extensions).inhibitAnyPolicy();
    if (extConf == null) {
      return;
    }

    int skipCerts = extConf.skipCerts();
    if (skipCerts < 0) {
      throw new CertprofileException(
          "negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
    }

    boolean critical = critical(type);
    this.inhibitAnyPolicy = new ExtensionValue(critical,
        new Asn1Integer(BigInteger.valueOf(skipCerts)));
  }

  private void initKeyUsage(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.keyUsage.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.KeyUsage extConf = getExtension(type, extensions).keyUsage();
    if (extConf != null) {
      this.keyUsage = extConf.toXiKeyUsageOptions();
    }
  }

  private void initNameConstraints(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.nameConstraints.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.NameConstraints extConf = getExtension(type, extensions).nameConstraints();
    if (extConf == null) {
      return;
    }

    boolean critical = critical(type);
    this.nameConstraints = ExtensionValue.build(critical, extConf.toNameConstraints());
  }

  private void initPolicyConstraints(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    Asn1Oid type = ExtensionID.policyConstraints.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.PolicyConstraints extConf =
        getExtension(type, extensions).policyConstraints();
    if (extConf == null) {
      return;
    }

    Integer require = extConf.requireExplicitPolicy();
    if (require != null && require < 0) {
      throw new CertprofileException("negative requireExplicitPolicy is not allowed: " + require);
    }

    Integer inhibit = extConf.inhibitPolicyMapping();
    if (inhibit != null && inhibit < 0) {
      throw new CertprofileException("negative inhibitPolicyMapping is not allowed: " + inhibit);
    }

    if (require == null && inhibit == null) {
      return;
    }

    BigInteger requireBn = require == null ? null : BigInteger.valueOf(require);
    BigInteger inhibitBn = inhibit == null ? null : BigInteger.valueOf(inhibit);

    boolean critical = critical(type);
    this.policyConstraints = ExtensionValue.build(critical,
        new PolicyConstraints(requireBn, inhibitBn));
  } // method initPolicyConstraints

  private void initPrivateKeyUsagePeriod(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.privateKeyUsagePeriod.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
      ExtensionValueConf.PrivateKeyUsagePeriod extConf =
          getExtension(type, extensions).privateKeyUsagePeriod();
      if (extConf != null) {
        privateKeyUsagePeriod = Validity.getInstance(extConf.validity());
      }
    }
  }

  private void initPolicyMappings(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.policyMappings.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.PolicyMappings extConf = getExtension(type, extensions).policyMappings();
    if (extConf == null) {
      return;
    }

    boolean critical = critical(type);
    this.policyMappings = ExtensionValue.build(critical, extConf.toPolicyMappings());
  }

  private void initQcStatements(Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException, CodecException {
    Asn1Oid type = ExtensionID.qcStatements.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.QcStatements extConf = getExtension(type, extensions).qcStatements();
    if (extConf == null) {
      return;
    }

    List<ExtensionValueConf.QcStatementType> qcStatementTypes = extConf.qcStatements();
    this.qcStatementsOption = new ArrayList<>(qcStatementTypes.size());
    Set<String> currencyCodes = new HashSet<>();
    boolean requireInfoFromReq = false;

    for (ExtensionValueConf.QcStatementType m : qcStatementTypes) {
      QCStatementID qcStatementId = m.statementId();
      ExtensionValueConf.QcStatementValueType statementValue = m.statementValue();
      QcStatementOption qcStatementOption;
      if (statementValue == null) {
        qcStatementOption = new QcStatementOption(QCStatement.create(qcStatementId.oid()));
      } else if (statementValue.qcRetentionPeriod() != null) {
        QCStatement qcStatement = QCStatement.create(qcStatementId.oid(),
            new Asn1Integer(BigInteger.valueOf(statementValue.qcRetentionPeriod())));
        qcStatementOption = new QcStatementOption(qcStatement);
      } else if (statementValue.constant() != null) {
        Asn1Primitive constantStatementValue;
        try {
          constantStatementValue = statementValue.constant().toASN1();
        } catch (CodecException ex) {
          throw new CertprofileException("can not parse the constant value of QcStatement");
        }
        qcStatementOption = new QcStatementOption(
            QCStatement.create(qcStatementId.oid(), constantStatementValue));
      } else if (statementValue.qcEuLimitValue() != null) {
        ExtensionValueConf.QcEuLimitValueType euLimitType = statementValue.qcEuLimitValue();
        String tmpCurrency = euLimitType.currency().toUpperCase();
        if (currencyCodes.contains(tmpCurrency)) {
          throw new CertprofileException("Duplicated definition of qcStatements with " +
              "QCEuLimitValue for the currency " + tmpCurrency);
        }

        Iso4217CurrencyCode currency = StringUtil.isNumber(tmpCurrency)
            ? Iso4217CurrencyCode.ofNumeric(Integer.parseInt(tmpCurrency))
            : Iso4217CurrencyCode.ofAlphabetic(tmpCurrency);

        ExtensionValueConf.Range2Type r1 = euLimitType.amount();
        ExtensionValueConf.Range2Type r2 = euLimitType.exponent();
        if (r1.min() == r1.max() && r2.min() == r2.max()) {
          MonetaryValue monetaryValue = new MonetaryValue(currency, r1.min(), r2.min());
          qcStatementOption = new QcStatementOption(
                                QCStatement.create(qcStatementId.oid(), monetaryValue));
        } else {
          qcStatementOption = new QcStatementOption(qcStatementId.oid(),
                                new MonetaryValueOption(currency, r1, r2));
          requireInfoFromReq = true;
        }
        currencyCodes.add(tmpCurrency);
      } else if (statementValue.pdsLocations() != null) {
        List<PdsLocation> vec = new LinkedList<>();
        for (ExtensionValueConf.PdsLocationType pl : statementValue.pdsLocations()) {
          String lang = pl.language();
          vec.add(new PdsLocation(pl.url(), lang));
        }

        qcStatementOption = new QcStatementOption(
            QCStatement.create(qcStatementId.oid(), new PdsLocations(vec)));
      } else {
        throw new CertprofileException("unknown value of qcStatement");
      }

      this.qcStatementsOption.add(qcStatementOption);
    } // end for

    if (requireInfoFromReq) {
      return;
    }

    List<QCStatement> vec = new LinkedList<>();
    for (QcStatementOption m : qcStatementsOption) {
      if (m.statement() == null) {
        throw new IllegalStateException("should not reach here");
      }
      vec.add(m.statement());
    }
    qcStatements = new ExtensionValue(critical(type), new QCStatements(vec).toAsn1Primitive());
    qcStatementsOption = null;
  } // method initQcStatements

  private void initSmimeCapabilities(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.smimeCapabilities.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);

    ExtensionValueConf.SmimeCapabilities extConf =
        getExtension(type, extensions).smimeCapabilities();
    if (extConf == null) {
      return;
    }

    List<ExtensionValueConf.SmimeCapability> list = extConf.capabilities();

    boolean critical = critical(type);
    List<SMIMECapability> vec = new LinkedList<>();
    for (ExtensionValueConf.SmimeCapability m : list) {
      Asn1Oid oid = m.capabilityId();
      Asn1Primitive params = null;
      Integer capParams = m.parameter();
      if (capParams != null) {
        params = new Asn1Integer(BigInteger.valueOf(capParams));
      }
      vec.add(new SMIMECapability(oid, params));
    }

    smimeCapabilities = new ExtensionValue(critical, new SMIMECapabilities(vec).toAsn1Primitive());
  } // method initSmimeCapabilities

  private void initSubjectAlternativeName(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions)
          throws CertprofileException {
    Asn1Oid type = ExtensionID.subjectAlternativeName.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    GeneralNameType extConf = getExtension(type, extensions).subjectAltName();
    if (extConf != null) {
      this.subjectAltNameModes = extConf.modes();
      if (extConf.otherNameTypes() == null) {
        this.subjectAltNameOtherNameTypes = null;
      } else {
        this.subjectAltNameOtherNameTypes = new HashSet<>();
        for (String str : extConf.otherNameTypes()) {
          OtherNameID onId = OtherNameID.ofOidOrName(str);
          if (onId == null) {
            throw new CertprofileException("unknown otherNameType " + str);
          }
          this.subjectAltNameOtherNameTypes.add(onId.oid());
        }
      }
    }
  } // method initSubjectAlternativeName

  private void initSubjectToSubjectAltNames(List<RdnType> list) throws CertprofileException {
    if (CollectionUtil.isEmpty(list)) {
      return;
    }

    subjectToSubjectAltNameModes = new HashMap<>();
    for (RdnType m : list) {
      GeneralNameTag targetTag = m.toSAN();
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
      if (m.type() == AttributeType.emailAddress) {
        // we allow targetTag to be null to generate legacy certificates.
        if (targetTag != null && targetTag != GeneralNameTag.rfc822Name) {
          throw new CertprofileException("toSAN != rfc822Name: " + targetTag);
        }
      }

      if (targetTag == null) {
        continue;
      }

      if (!subjectAltNameModes.contains(targetTag)) {
        throw new CertprofileException("target tag " + targetTag + " not allowed in SAN");
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

      subjectToSubjectAltNameModes.put(m.type().oid(), targetTag);
    }
  } // method initSubjectToSubjectAltNames

  private void initSubjectInfoAccess(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.subjectInfoAccess.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.SubjectInfoAccess extConf =
        getExtension(type, extensions).subjectInfoAccess();
    if (extConf == null) {
      return;
    }

    List<ExtensionValueConf.Access> list = extConf.accesses();
    this.subjectInfoAccessModes = new HashMap<>();
    for (ExtensionValueConf.Access entry : list) {
      this.subjectInfoAccessModes.put(entry.accessMethod().oid(), entry.accessLocation().modes());
    }
  } // method initSubjectInfoAccess

  private void initSubjectDirectoryAttributeTypes(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    Asn1Oid type = ExtensionID.subjectDirectoryAttributes.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.SubjectDirectoryAttributes extConf =
        getExtension(type, extensions).subjectDirectoryAttributes();
    if (extConf == null) {
      // allow all attributes
      return;
    }

    List<String> list = extConf.types();
    this.subjectDirectoryAttributes = new ArrayList<>(list.size());
    for (String attrType : list) {
      SubjectDirectoryAttributeType o = SubjectDirectoryAttributeType.ofOidOrName(attrType);
      if (o == null) {
        throw new CertprofileException("invalid SubjectDirectoryAttribute type " + attrType);
      }
      this.subjectDirectoryAttributes.add(o.oid());
    }

    if (this.subjectDirectoryAttributes.isEmpty()) {
      throw new CertprofileException("SubjectDirectoryAttribute does not have non-empty types");
    }
  } // method initSubjectDirectoryAttributeTypes

  private void initTlsFeature(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.tlsFeature.oid();
    if (!extensionsControl.containsID(type)) {
      return;
    }

    extnIds.remove(type);
    ExtensionValueConf.TlsFeature extConf = getExtension(type, extensions).tlsFeature();
    if (extConf == null) {
      return;
    }

    List<Integer> list = new ArrayList<>(extConf.features().size());
    list.addAll(extConf.features());
    Collections.sort(list);

    int[] features = new int[list.size()];
    int idx = 0;
    for (Integer m : list) {
      features[idx++] = m;
    }
    boolean critical = critical(type);
    tlsFeature = new ExtensionValue(critical, new TLSFeatures(features).toAsn1Primitive());
  }

  private void initCCCExtensionSchemas(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions)
      throws CertprofileException {
    Asn1Oid type = null;
    for (Asn1Oid m : extnIds) {
      if (m.on(ExtensionOIDs.id_ccc_extn)) {
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

    List<Asn1Oid> simpleSchemaTypes = Arrays.asList(
        ExtensionID.CCC_F_External_CACert.oid(),
        ExtensionID.CCC_J_VehicleOEMCACert.oid(),
        ExtensionID.CCC_K_VehicleCert.oid(),
        ExtensionID.CCC_M_VehicleOEMCACert.oid(),
        ExtensionID.CCC_P_VehicleOEMEncCert.oid(),
        ExtensionID.CCC_Q_VehicleOEMSigCert.oid(),
        ExtensionID.CCC_R_CertificationBodyCert.oid(),
        ExtensionID.CCC_S_SBxDKisIntermediateCACert.oid(),
        ExtensionID.CCC_U_SBxDKisRootCACert.oid(),
        ExtensionID.CCC_DeviceEncCert.oid(),
        ExtensionID.CCC_VehicleIntermediateCert.oid());

    if (simpleSchemaTypes.contains(type)) {
      ExtensionValueConf.CCCSimpleExtensionSchema schema = ex.cccExtensionSchema();
      int version = (schema == null) ? 1 : schema.version();
      this.cccSimpleExtensionSchemaValue = new ExtensionValue(ex.isCritical(),
          new SimpleExtensionSchema(version).toAsn1Primitive());
      this.cccExtensionSchemaType = type;
    } else if (ExtensionID.CCC_E_Instance_CACert.oid().equals(type) ||
        ExtensionID.CCC_H_EndpointCert.oid().equals(type) ||
        ExtensionID.CCC_T_SBxDKisEndpointCert.oid().equals(type)) {
      this.cccExtensionSchemaType = type;
    }
  }

  private void initMicrosoftExtensions(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.microsoft_CertificateTemplateName.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
      ExtensionValueConf.MicrosoftCertificateTemplateName extConf =
          getExtension(type, extensions).microsoftCertificateTemplateName();
      if (extConf == null) {
        return;
      }

      Asn1Primitive extnValue = extConf.toExtensionValue();
      boolean critical = critical(type);
      microsoftCertTemplateName = new ExtensionValue(critical, extnValue);
    }

    type = ExtensionID.microsoft_CertificateTemplateInformation.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
      ExtensionValueConf.MicrosoftCertificateTemplateInformation extConf =
          getExtension(type, extensions).microsoftCertificateTemplateInformation();
      if (extConf == null) {
        return;
      }

      boolean critical = critical(type);
      microsoftCertTemplateInformation = new ExtensionValue(critical, extConf.toExtensionValue());
    }

    type = ExtensionID.microsoft_SID.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
      ExtensionValueConf.MicrosoftSID extConf = getExtension(type, extensions).microsoftSID();
      if (extConf == null) {
        return;
      }

      microsoftSID = extConf;
    }
  }

  private void initSpdmExtensions(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) throws CertprofileException {
    Asn1Oid type = ExtensionID.SPDM_Extension.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
      ExtensionValueConf.SpdmCertOids extConf = getExtension(type, extensions).spdmCertOids();
      if (extConf == null) {
        throw new CertprofileException("spdmCertOids is not present");
      }

      List<SpdmCertOid> list = new LinkedList<>();
      for (ExtensionValueConf.SpdmCertOid oid : extConf.oids()) {
        String oidType = oid.type();
        Asn1Oid asn1Oid = null;
        if (oidType.contains(".")) {
          try {
            asn1Oid = new Asn1Oid(oidType);
          } catch (Exception e) {
          }
        }

        if (asn1Oid == null) {
          if ("DMTF-hardware-identity".equalsIgnoreCase(oidType)) {
            asn1Oid = SpdmOIDs.id_DMTF_hardware_identity;
          } else if ("DMTF-mutable-certificate".equalsIgnoreCase(oidType)) {
            asn1Oid = SpdmOIDs.id_DMTF_mutable_certificate;
          }
        }

        if (asn1Oid == null) {
          throw new CertprofileException("invalid SpdmCertOid.type " + oidType);
        }

        list.add(new SpdmCertOid(asn1Oid, oid.definition()));
      }

      spdmCertOids = ExtensionValue.build(critical(type), new SpdmCertOids(list));
    }
  }

  private void initStirExtensions(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) throws CertprofileException {
    Asn1Oid type = ExtensionID.STIR_JWTClaimConstraints.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
      ExtensionValueConf.JWTClaimConstraints extConf =
          getExtension(type, extensions).stirJWTClaimConstraints();
      if (extConf == null) {
        throw new CertprofileException("stirJWTClaimConstraints is not present");
      }

      JWTClaimNames mustInclude = null;
      if (extConf.mustInclude() != null) {
        mustInclude = new JWTClaimNames(extConf.mustInclude().toArray(new String[0]));
      }

      JWTClaimPermittedValuesList valuesList = null;
      if (extConf.permittedValues() != null) {
        List<JWTClaimPermittedValues> pv = new LinkedList<>();
        for (ExtensionValueConf.JWTClaimPermittedValues m : extConf.permittedValues()) {
          pv.add(new JWTClaimPermittedValues(m.claim(), m.permitted()));
        }
        valuesList = new JWTClaimPermittedValuesList(pv);
      }

      JWTClaimConstraints v = new JWTClaimConstraints(mustInclude, valuesList);
      stirJWTClaimPermittedValues = ExtensionValue.build(critical(type), v);
    }
  }

  private void initRfc8226Extensions(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.STIR_JWTClaimConstraints.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
    }
  }

  private void initBrskiExtensions(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.masaUrl.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
      ExtensionValueConf.MasaUrl extConf = getExtension(type, extensions).masaUrl();
      this.masaUrl = (extConf == null) ? null
          : new ExtensionValue(critical(type), new Asn1IA5String(extConf.url()));
    }
  }

  private void initMrtdExtensions(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) throws CertprofileException {
    Asn1Oid type = ExtensionID.MRTD_NameChange.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
    }

    type = ExtensionID.MRTD_DocumentTypeList.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
      ExtensionValueConf.MrtdDocumentTypeListSyntax extConf =
          getExtension(type, extensions).mrtdDocumentTypes();
      if (extConf == null) {
        throw new CertprofileException("mrtdDocumentTypes is not present for the extension "
            + type.getId());
      }
      this.mrtdDocumentTypes = ExtensionValue.build(critical(type),
          new DocumentTypeListSyntax(extConf.types()));
    }
  }

  private void initDiceExtensions(
      Set<Asn1Oid> extnIds, Map<String, ExtensionType> extensions) {
    Asn1Oid type = ExtensionID.dice_ueid.oid();
    if (extensionsControl.containsID(type)) {
      extnIds.remove(type);
    }
  }

  public static GeneralNames createRequestedSubjectAltNames(
      X500Name reqSubject, GeneralNames sanExtnValue, Set<GeneralNameTag> subjectAltNameModes,
      Map<Asn1Oid, GeneralNameTag> subjectToSubjectAltNameModes,
      Set<Asn1Oid> otherNameTypes)
      throws BadCertTemplateException {
    List<GeneralName> list = new LinkedList<>();

    if (sanExtnValue != null) {
      for (GeneralName generalName : sanExtnValue) {
        list.add(ProfileUtil.createGeneralName(generalName, subjectAltNameModes, otherNameTypes));
      }
    }

    if (subjectToSubjectAltNameModes != null) {
      for (Asn1Oid attrType : subjectToSubjectAltNameModes.keySet()) {
        GeneralNameTag targetTag = subjectToSubjectAltNameModes.get(attrType);

        List<RDN> rdns = reqSubject.getRDNs(attrType);
        if (rdns == null) {
          continue;
        }

        for (RDN rdn : rdns) {
          String text = X509Util.rdnValueToString(rdn.getFirst().getValue());
          if (subjectAltNameModes == null || subjectAltNameModes.contains(targetTag)) {
            list.add(GeneralName.ofTagName(targetTag.tag(), text));
          }
        }
      }
    }

    return list.isEmpty() ? null : new GeneralNames(list.toArray(new GeneralName[0]));
  }

  public AuthorityInfoAccessControl aiaControl() {
    return aiaControl;
  }

  public ExtensionValueConf.BiometricInfo biometricInfo() {
    return biometricInfo;
  }

  public Validity privateKeyUsagePeriod() {
    return privateKeyUsagePeriod;
  }

  public ExtensionValue qcStatements() {
    return qcStatements;
  }

  List<QcStatementOption> qcStatementsOption() {
    return qcStatementsOption;
  }

  public Set<GeneralNameTag> subjectAltNameModes() {
    return subjectAltNameModes;
  }

  public Set<Asn1Oid> subjectAltNameOtherNameTypes() {
    return subjectAltNameOtherNameTypes;
  }

  public Map<Asn1Oid, GeneralNameTag> subjectToSubjectAltNameModes() {
    return subjectToSubjectAltNameModes;
  }

  public Map<Asn1Oid, Set<GeneralNameTag>> subjectInfoAccessModes() {
    return subjectInfoAccessModes;
  }

  public List<Asn1Oid> subjectDirectoryAttributes() {
    return subjectDirectoryAttributes;
  }

  public CertificatePolicies certificatePolicies() {
    return certificatePolicies;
  }

  public Map<Asn1Oid, ExtensionValue> constantExtensions() {
    return constantExtensions;
  }

  public Set<ExtKeyUsageControl> extendedKeyusages() {
    return extendedKeyusages;
  }

  public ExtensionsControl extensionControls() {
    return extensionsControl;
  }

  public SubjectKeyIdentifierControl subjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public ExtensionValue inhibitAnyPolicy() {
    return inhibitAnyPolicy;
  }

  public Set<KeySingleUsage> getKeyUsage(KeySpec keySpec) {
    return keyUsage == null ? null : keyUsage.getUsages(keySpec);
  }

  public ExtensionValue nameConstraints() {
    return nameConstraints;
  }

  public Integer pathLen() {
    return pathLen;
  }

  public ExtensionValue policyConstraints() {
    return policyConstraints;
  }

  public ExtensionValue policyMappings() {
    return policyMappings;
  }

  public ExtensionValue smimeCapabilities() {
    return smimeCapabilities;
  }

  public ExtensionValue tlsFeature() {
    return tlsFeature;
  }

  public Asn1Oid cccExtensionSchemaType() {
    return cccExtensionSchemaType;
  }

  public ExtensionValue cccSimpleExtensionSchemaValue() {
    return cccSimpleExtensionSchemaValue;
  }

  public ExtensionValue microsoftCertTemplateName() {
    return microsoftCertTemplateName;
  }

  public ExtensionValue microsoftCertTemplateInformation() {
    return microsoftCertTemplateInformation;
  }

  public ExtensionValueConf.MicrosoftSID microsoftSID() {
    return microsoftSID;
  }

  public ExtensionValue spdmCertOids() {
    return spdmCertOids;
  }

  public ExtensionValue stirJWTClaimPermittedValues() {
    return stirJWTClaimPermittedValues;
  }

  public ExtensionValue masaUrl() {
    return masaUrl;
  }

  public ExtensionValue mrtdDocumentTypes() {
    return mrtdDocumentTypes;
  }

  public List<Asn1Oid> extensionIDs() {
    return extensionIDs;
  }

  private static ExtensionType getExtension(
      Asn1Oid type, Map<String, ExtensionType> extensions) {
    return Optional.ofNullable(extensions.get(type.getId())).orElseThrow(() ->
        new IllegalStateException("should not reach here: undefined extension "
          + OIDs.oidToDisplayName(type)));
  }

  private boolean critical(Asn1Oid type) {
    return extensionsControl.getControl(type).isCritical();
  }

}
