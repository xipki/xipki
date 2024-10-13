// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.profile.BaseCertprofile;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.KeypairGenControl;
import org.xipki.ca.api.profile.NotAfterMode;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.api.profile.SubjectDnSpec;
import org.xipki.ca.api.profile.SubjectKeyIdentifierControl;
import org.xipki.ca.api.profile.TextVadidator;
import org.xipki.ca.certprofile.xijson.conf.KeypairGenerationType;
import org.xipki.ca.certprofile.xijson.conf.KeypairGenerationType.KeyType;
import org.xipki.ca.certprofile.xijson.conf.Subject;
import org.xipki.ca.certprofile.xijson.conf.Subject.RdnType;
import org.xipki.ca.certprofile.xijson.conf.Subject.ValueType;
import org.xipki.ca.certprofile.xijson.conf.X509ProfileType;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements.Range2Type;
import org.xipki.pki.BadCertTemplateException;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.SignAlgo;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.TripleState;
import org.xipki.util.Validity;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.Vector;

/**
 * Certprofile configured in JSON.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class XijsonCertprofile extends BaseCertprofile {

  private static final Logger LOG = LoggerFactory.getLogger(XijsonCertprofile.class);

  private CertDomain certDomain;

  private CertLevel certLevel;

  private KeypairGenControl keypairGenControl;

  private String serialNumberMode;

  private Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms;

  private Integer maxSize;

  private NotBeforeOption notBeforeOption;

  private List<SignAlgo> signatureAlgorithms;

  private SubjectControl subjectControl;

  private Validity validity;

  private boolean hasNoWellDefinedExpirationDate;

  private NotAfterMode notAfterMode;

  private X509CertVersion version;

  private XijsonExtensions extensions;

  private void reset() {
    certDomain = null;
    certLevel = null;
    keypairGenControl = null;
    serialNumberMode = null;
    keyAlgorithms = null;
    maxSize = null;
    signatureAlgorithms = null;
    notBeforeOption = null;
    subjectControl = null;
    validity = null;
    hasNoWellDefinedExpirationDate = false;
    notAfterMode = null;
    version = null;
    extensions = null;
  } // method reset

  @Override
  public void initialize(String data) throws CertprofileException {
    X509ProfileType conf;
    try {
      byte[] bytes = StringUtil.toUtf8Bytes(Args.notBlank(data, "data"));
      conf = X509ProfileType.parse(bytes);
    } catch (RuntimeException ex) {
      LogUtil.error(LOG, ex);
      throw new CertprofileException("caught RuntimeException while parsing certprofile: " + ex.getMessage());
    }

    initialize(conf);

  } // method initialize

  public void initialize(X509ProfileType conf) throws CertprofileException {
    Args.notNull(conf, "conf");

    reset();
    try {
      initialize0(conf);
    } catch (RuntimeException ex) {
      LogUtil.error(LOG, ex);
      throw new CertprofileException("caught RuntimeException while initializing certprofile: " + ex.getMessage());
    }
  } // method initialize

  private void initialize0(X509ProfileType conf) throws CertprofileException {
    this.version = conf.getVersion();
    if (this.version == null) {
      this.version = X509CertVersion.v3;
    }

    if (conf.getSignatureAlgorithms() != null) {
      List<String> algoNames = conf.getSignatureAlgorithms();
      List<SignAlgo> list = new ArrayList<>(algoNames.size());
      for (String algoName : algoNames) {
        try {
          list.add(SignAlgo.getInstance(algoName));
        } catch (NoSuchAlgorithmException ex) {
          LOG.warn("unsupported signature algorithm: {}, ignore it", algoName);
        }
      }

      if (list.isEmpty()) {
        throw new CertprofileException("none of the signature algorithms is supported: "
            + conf.getSignatureAlgorithms());
      }

      this.signatureAlgorithms = Collections.unmodifiableList(list);
    }

    this.maxSize = conf.getMaxSize();

    if ("99991231235959Z".equalsIgnoreCase(conf.getValidity())) {
      this.hasNoWellDefinedExpirationDate = true;
      this.validity = null;
    } else {
      this.hasNoWellDefinedExpirationDate = false;
      this.validity = Validity.getInstance(conf.getValidity());
    }
    this.notAfterMode = conf.getNotAfterMode();
    this.certLevel = conf.getCertLevel();
    if (this.certLevel == null) {
      throw new CertprofileException("invalid CertLevel");
    }

    this.certDomain = conf.getCertDomain() == null ? CertDomain.RFC5280 : conf.getCertDomain();

    // KeypairGenControl
    KeypairGenerationType kg = conf.getKeypairGeneration();

    this.serialNumberMode = conf.getSerialNumberMode();

    if (kg == null || booleanValue(kg.getForbidden(), false)) {
      this.keypairGenControl = KeypairGenControl.ForbiddenKeypairGenControl.INSTANCE;
    } else if (booleanValue(kg.getInheritCA(), false)) {
      this.keypairGenControl = KeypairGenControl.InheritCAKeypairGenControl.INSTANCE;
    } else {
      KeyType keyType = kg.getKeyType();
      ASN1ObjectIdentifier keyAlgOid = new ASN1ObjectIdentifier(kg.getAlgorithm().getOid());
      Map<String, String> params = kg.getParameters();

      if (keyType == KeyType.RSA) {
        int keySize = Integer.parseInt(params.get(KeypairGenerationType.PARAM_keysize));
        this.keypairGenControl = new KeypairGenControl.RSAKeypairGenControl(keySize, keyAlgOid);
      } else if (keyType == KeyType.EC) {
        ASN1ObjectIdentifier curveOid = new ASN1ObjectIdentifier(params.get(KeypairGenerationType.PARAM_curve));
        this.keypairGenControl = new KeypairGenControl.ECKeypairGenControl(curveOid, keyAlgOid);
      } else if (keyType == KeyType.ED25519 || keyType == KeyType.ED448
          || keyType == KeyType.X25519 || keyType == KeyType.X448) {
        this.keypairGenControl = new KeypairGenControl.EDDSAKeypairGenControl(keyAlgOid);
      } else {
        throw new CertprofileException("unknown KeypairGeneration type " + keyType);
      }
    }

    String str = conf.getNotBeforeTime().toLowerCase().trim();
    Long offsetSeconds = null;
    ZoneId midnightTimeZone = null;
    if (str.startsWith("midnight")) {
      int seperatorIdx = str.indexOf(':');
      String timezoneId = (seperatorIdx == -1) ? "GMT+0" : str.substring(seperatorIdx + 1).toUpperCase();
      final List<String> validIds = Arrays.asList(
          "GMT+0", "GMT+1", "GMT+2", "GMT+3", "GMT+4", "GMT+5",
          "GMT+6", "GMT+7", "GMT+8", "GMT+9", "GMT+10", "GMT+11", "GMT+12",
          "GMT-0", "GMT-1", "GMT-2", "GMT-3", "GMT-4", "GMT-5",
          "GMT-6", "GMT-7", "GMT-8", "GMT-9", "GMT-10", "GMT-11", "GMT-12");

      if (!validIds.contains(timezoneId)) {
        throw new CertprofileException("invalid time zone id " + timezoneId);
      }

      midnightTimeZone = ZoneId.of(timezoneId);
    } else if ("current".equalsIgnoreCase(str)) {
      offsetSeconds = 0L;
    } else if (str.length() > 2) {
      char sign = str.charAt(0);
      char suffix = str.charAt(str.length() - 1);
      if (sign == '+' || sign == '-') {
        long digit = Long.parseLong(str.substring(1, str.length() - 1));
        long seconds;
        if (suffix == 'd') {
          seconds = digit * (24L * 60 * 60);
        } else if (suffix == 'h') {
          seconds = digit * (60L * 60);
        } else if (suffix == 'm') {
          seconds = digit * 60L;
        } else if (suffix == 's') {
          seconds = digit;
        } else {
          throw new CertprofileException("invalid notBefore " + str);
        }
        offsetSeconds = (sign == '+') ? seconds : -1 * seconds;
      } else {
        throw new CertprofileException("invalid notBefore '" + str + "'");
      }
    } else {
      throw new CertprofileException("invalid notBefore '" + str + "'");
    }

    notBeforeOption = (offsetSeconds != null) ? NotBeforeOption.getOffsetOption(offsetSeconds)
        : NotBeforeOption.getMidNightOption(midnightTimeZone);

    // KeyAlgorithms
    this.keyAlgorithms = conf.toXiKeyAlgorithms();

    // Subject
    Subject subject = conf.getSubject();
    List<RdnControl> subjectDnControls = new LinkedList<>();

    for (RdnType rdn : subject.getRdns()) {
      ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(rdn.getType().getOid());

      Range range = (rdn.getMinLen() != null || rdn.getMaxLen() != null)
          ? new Range(rdn.getMinLen(), rdn.getMaxLen()) :  null;

      ValueType value = rdn.getValue();
      RdnControl rdnControl = (value == null)
          ? new RdnControl(type, rdn.minOccurs(), rdn.maxOccurs())
          : new RdnControl(type, value.getText(), value.isOverridable());

      subjectDnControls.add(rdnControl);

      rdnControl.setStringType(rdn.getStringType());
      rdnControl.setStringLengthRange(range);
      if (rdn.getRegex() != null) {
        rdnControl.setPattern(TextVadidator.compile(rdn.getRegex()));
      }
      rdnControl.setPrefix(rdn.getPrefix());
      rdnControl.setSuffix(rdn.getSuffix());
      rdnControl.setGroup(rdn.getGroup());
      if (rdn.getNotInSubject() != null) {
        rdnControl.setNotInSubject(rdn.getNotInSubject());
      }

      SubjectDnSpec.fixRdnControl(rdnControl);
    }

    this.subjectControl = new SubjectControl(subjectDnControls, subject.keepRdnOrder());

    // Extensions
    this.extensions = new XijsonExtensions(this, conf, subjectControl);
  } // method initialize0

  @Override
  public boolean hasNoWellDefinedExpirationDate() {
    return this.hasNoWellDefinedExpirationDate;
  }

  @Override
  public Validity getValidity() {
    return validity;
  }

  @Override
  public NotAfterMode getNotAfterMode() {
    return notAfterMode != null ? notAfterMode : super.getNotAfterMode();
  }

  @Override
  protected void verifySubjectDnOccurrence(X500Name requestedSubject) throws BadCertTemplateException {
    ASN1ObjectIdentifier[] types = Args.notNull(requestedSubject, "requestedSubject").getAttributeTypes();

    Map<ASN1ObjectIdentifier, GeneralNameTag> subjectToSubjectAltNameModes =
        extensions.getSubjectToSubjectAltNameModes();

    for (ASN1ObjectIdentifier type : types) {
      RdnControl occu = subjectControl.getControl(type);
      if (occu == null) {
        if (subjectToSubjectAltNameModes != null && subjectToSubjectAltNameModes.containsKey(type)) {
          continue;
        } else {
          throw new BadCertTemplateException(String.format(
              "subject DN of type %s is not allowed", ObjectIdentifiers.oidToDisplayName(type)));
        }
      } else {
        if (!occu.isValueOverridable()) {
          throw new BadCertTemplateException(String.format(
              "subject DN of type %s is not allowed in the request", ObjectIdentifiers.oidToDisplayName(type)));
        }
      }

      RDN[] rdns = requestedSubject.getRDNs(type);
      if (rdns.length > occu.getMaxOccurs() || rdns.length < occu.getMinOccurs()) {
        throw new BadCertTemplateException(String.format(
            "occurrence of subject DN of type %s not within the allowed range. "
            + "%d is not within [%d, %d]", ObjectIdentifiers.oidToDisplayName(type), rdns.length,
            occu.getMinOccurs(), occu.getMaxOccurs()));
      }
    }

    for (ASN1ObjectIdentifier m : subjectControl.getTypes()) {
      RdnControl occurrence = subjectControl.getControl(m);
      if (occurrence.getValue() != null) {
        continue;
      }

      if (occurrence.getMinOccurs() == 0) {
        continue;
      }

      boolean present = false;
      for (ASN1ObjectIdentifier type : types) {
        if (occurrence.getType().equals(type)) {
          present = true;
          break;
        }
      }

      if (!present) {
        throw new BadCertTemplateException(String.format(
            "required subject DN of type %s is not present", ObjectIdentifiers.oidToDisplayName(occurrence.getType())));
      }
    }
  } // method verifySubjectDnOccurrence

  @Override
  public ExtensionValues getExtensions(
      Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls, X500Name requestedSubject,
      X500Name grantedSubject, Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Instant notBefore, Instant notAfter, PublicCaInfo caInfo)
      throws CertprofileException, BadCertTemplateException {
    ExtensionValues values = new ExtensionValues();
    if (CollectionUtil.isEmpty(extensionControls)) {
      return values;
    }

    Args.notNull(requestedSubject, "requestedSubject");
    Args.notNull(notBefore, "notBefore");
    Args.notNull(notAfter, "notAfter");

    Set<ASN1ObjectIdentifier> occurrences = new HashSet<>(extensionControls.keySet());

    // AuthorityKeyIdentifier
    // processed by the CA

    // SubjectKeyIdentifier
    // processed by the CA

    // KeyUsage
    // processed by the CA

    // CertificatePolicies
    // processed by the CA

    // Policy Mappings
    ASN1ObjectIdentifier type = Extension.policyMappings;

    ExtensionValue policyMappings = extensions.getPolicyMappings();
    if (policyMappings != null) {
      if (occurrences.remove(type)) {
        values.addExtension(type, policyMappings);
      }
    }

    // SubjectAltName
    type = Extension.subjectAlternativeName;
    if (occurrences.contains(type)) {
      GeneralNames genNames = extensions.createRequestedSubjectAltNames(
          requestedSubject, grantedSubject, requestedExtensions);
      if (genNames != null) {
        ExtensionValue value = new ExtensionValue(extensionControls.get(type).isCritical(), genNames);
        values.addExtension(type, value);
        occurrences.remove(type);
      }
    }

    // IssuerAltName
    // processed by the CA

    // Subject Directory Attributes
    type = Extension.subjectDirectoryAttributes;
    Extension extension = (requestedExtensions == null) ? null : requestedExtensions.get(type);

    SubjectDirectoryAttributesControl subjectDirAttrsControl = extensions.getSubjectDirAttrsControl();
    if (occurrences.contains(type) && subjectDirAttrsControl != null && extension != null) {
      ASN1GeneralizedTime dateOfBirth = null;
      String placeOfBirth = null;
      String gender = null;
      List<String> countryOfCitizenshipList = new LinkedList<>();
      List<String> countryOfResidenceList = new LinkedList<>();
      Map<ASN1ObjectIdentifier, List<ASN1Encodable>> otherAttrs = new HashMap<>();

      Vector<?> reqSubDirAttrs = SubjectDirectoryAttributes.getInstance(extension.getParsedValue()).getAttributes();
      for (Object reqSubDirAttr : reqSubDirAttrs) {
        Attribute attr = (Attribute) reqSubDirAttr;
        ASN1ObjectIdentifier attrType = attr.getAttrType();
        ASN1Encodable attrVal = attr.getAttributeValues()[0];

        if (ObjectIdentifiers.DN.placeOfBirth.equals(attrType)) {
          placeOfBirth = DirectoryString.getInstance(attrVal).getString();
        } else if (ObjectIdentifiers.DN.gender.equals(attrType)) {
          gender = ASN1PrintableString.getInstance(attrVal).getString();
        } else if (ObjectIdentifiers.DN.countryOfCitizenship.equals(attrType)) {
          String country = ASN1PrintableString.getInstance(attrVal).getString();
          countryOfCitizenshipList.add(country);
        } else if (ObjectIdentifiers.DN.countryOfResidence.equals(attrType)) {
          String country = ASN1PrintableString.getInstance(attrVal).getString();
          countryOfResidenceList.add(country);
        } else {
          List<ASN1Encodable> otherAttrVals = otherAttrs.computeIfAbsent(attrType, k -> new LinkedList<>());
          otherAttrVals.add(attrVal);
        }
      }

      Vector<Attribute> attrs = new Vector<>();
      for (ASN1ObjectIdentifier attrType : subjectDirAttrsControl.getTypes()) {
        if (ObjectIdentifiers.DN.placeOfBirth.equals(attrType)) {
          if (placeOfBirth != null) {
            attrs.add(new Attribute(attrType, new DERSet(new DERUTF8String(placeOfBirth))));
            continue;
          }
        } else if (ObjectIdentifiers.DN.gender.equals(attrType)) {
          if (gender != null && !gender.isEmpty()) {
            char ch = gender.charAt(0);
            if (!(gender.length() == 1
                && (ch == 'f' || ch == 'F' || ch == 'm' || ch == 'M'))) {
              throw new BadCertTemplateException("invalid gender " + gender);
            }
            attrs.add(new Attribute(attrType, new DERSet(new DERPrintableString(gender))));
            continue;
          }
        } else if (ObjectIdentifiers.DN.countryOfCitizenship.equals(attrType)) {
          if (!countryOfCitizenshipList.isEmpty()) {
            for (String country : countryOfCitizenshipList) {
              if (!SubjectDnSpec.isValidCountryAreaCode(country)) {
                throw new BadCertTemplateException("invalid countryOfCitizenship code " + country);
              }
              attrs.add(new Attribute(attrType, new DERSet(new DERPrintableString(country))));
            }
            continue;
          }
        } else if (ObjectIdentifiers.DN.countryOfResidence.equals(attrType)) {
          if (!countryOfResidenceList.isEmpty()) {
            for (String country : countryOfResidenceList) {
              if (!SubjectDnSpec.isValidCountryAreaCode(country)) {
                throw new BadCertTemplateException("invalid countryOfResidence code " + country);
              }
              attrs.add(new Attribute(attrType, new DERSet(new DERPrintableString(country))));
            }
            continue;
          }
        } else if (otherAttrs.containsKey(attrType)) {
          for (ASN1Encodable attrVal : otherAttrs.get(attrType)) {
            attrs.add(new Attribute(attrType, new DERSet(attrVal)));
          }

          continue;
        }

        throw new BadCertTemplateException("could not process type " + attrType.getId()
            + " in extension SubjectDirectoryAttributes");
      }

      SubjectDirectoryAttributes subjDirAttrs = new SubjectDirectoryAttributes(attrs);
      ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(), subjDirAttrs);
      values.addExtension(type, extValue);
      occurrences.remove(type);
    }

    // Basic Constraints
    // processed by the CA

    // Name Constraints
    type = Extension.nameConstraints;
    ExtensionValue nameConstraints = extensions.getNameConstraints();
    if (nameConstraints != null) {
      if (occurrences.remove(type)) {
        values.addExtension(type, nameConstraints);
      }
    }

    // PolicyConstrains
    type = Extension.policyConstraints;
    ExtensionValue policyConstraints = extensions.getPolicyConstraints();
    if (policyConstraints != null) {
      if (occurrences.remove(type)) {
        values.addExtension(type, policyConstraints);
      }
    }

    // ExtendedKeyUsage
    // processed by CA

    // CRL Distribution Points
    // processed by the CA

    // Inhibit anyPolicy
    type = Extension.inhibitAnyPolicy;
    ExtensionValue inhibitAnyPolicy = extensions.getInhibitAnyPolicy();
    if (inhibitAnyPolicy != null) {
      if (occurrences.remove(type)) {
        values.addExtension(type, inhibitAnyPolicy);
      }
    }

    // Freshest CRL
    // processed by the CA

    // Authority Information Access
    // processed by the CA

    // Subject Information Access
    // processed by the CA

    // OCSP Nocheck
    // processed by the CA

    // PrivateKeyUsagePeriod
    type = Extension.privateKeyUsagePeriod;
    if (occurrences.contains(type)) {
      Instant tmpNotAfter;
      Validity privateKeyUsagePeriod = extensions.getPrivateKeyUsagePeriod();
      if (privateKeyUsagePeriod == null) {
        tmpNotAfter = notAfter;
      } else {
        tmpNotAfter = privateKeyUsagePeriod.add(notBefore);
        if (tmpNotAfter.isAfter(notAfter)) {
          tmpNotAfter = notAfter;
        }
      }

      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new DERTaggedObject(false, 0, new DERGeneralizedTime(Date.from(notBefore))));
      vec.add(new DERTaggedObject(false, 1, new DERGeneralizedTime(Date.from(tmpNotAfter))));
      ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(), new DERSequence(vec));
      values.addExtension(type, extValue);
      occurrences.remove(type);
    }

    // QCStatements
    type = Extension.qCStatements;
    ExtensionValue qcStatments = extensions.getQcStatments();
    List<QcStatementOption> qcStatementsOption = extensions.getQcStatementsOption();
    if (occurrences.contains(type) && (qcStatments != null || qcStatementsOption != null)) {
      if (qcStatments != null) {
        values.addExtension(type, qcStatments);
        occurrences.remove(type);
      } else if (requestedExtensions != null) {
        // extract the data from request
        extension = requestedExtensions.get(type);
        if (extension == null) {
          throw new BadCertTemplateException("No QCStatement extension is contained in the request");
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(extension.getParsedValue());

        Map<String, int[]> qcEuLimits = new HashMap<>();
        final int n = seq.size();
        for (int i = 0; i < n; i++) {
          QCStatement stmt = QCStatement.getInstance(seq.getObjectAt(i));
          if (!Extn.id_etsi_qcs_QcLimitValue.equals(stmt.getStatementId())) {
            continue;
          }

          MonetaryValue monetaryValue = MonetaryValue.getInstance(stmt.getStatementInfo());
          int amount = monetaryValue.getAmount().intValue();
          int exponent = monetaryValue.getExponent().intValue();
          Iso4217CurrencyCode currency = monetaryValue.getCurrency();
          String currencyS = currency.isAlphabetic()
              ? currency.getAlphabetic().toUpperCase() : Integer.toString(currency.getNumeric());
          qcEuLimits.put(currencyS, new int[]{amount, exponent});
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (QcStatementOption m : qcStatementsOption) {
          if (m.getStatement() != null) {
            vec.add(m.getStatement());
            continue;
          }

          MonetaryValueOption monetaryOption = m.getMonetaryValueOption();
          String currencyS = monetaryOption.getCurrencyString();
          int[] limit = qcEuLimits.get(currencyS);
          if (limit == null) {
            throw new BadCertTemplateException("no EuLimitValue is specified for currency '" + currencyS + "'");
          }

          int amount = limit[0];
          Range2Type range = monetaryOption.getAmountRange();
          if (amount < range.getMin() || amount > range.getMax()) {
            throw new BadCertTemplateException("amount for currency '" + currencyS
                + "' is not within [" + range.getMin() + ", " + range.getMax() + "]");
          }

          int exponent = limit[1];
          range = monetaryOption.getExponentRange();
          if (exponent < range.getMin() || exponent > range.getMax()) {
            throw new BadCertTemplateException("exponent for currency '" + currencyS
                + "' is not within [" + range.getMin() + ", " + range.getMax() + "]");
          }

          MonetaryValue monetaryVale = new MonetaryValue(monetaryOption.getCurrency(), amount, exponent);
          QCStatement qcStatment = new QCStatement(m.getStatementId(), monetaryVale);
          vec.add(qcStatment);
        }

        ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(), new DERSequence(vec));
        values.addExtension(type, extValue);
        occurrences.remove(type);
      }
    }

    // BiometricData
    type = Extension.biometricInfo;
    extension = (requestedExtensions == null) ? null : requestedExtensions.get(type);
    BiometricInfoOption biometricInfo = extensions.getBiometricInfo();
    if (occurrences.contains(type) && biometricInfo != null && extension != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(extension.getParsedValue());
      final int n = seq.size();
      if (n < 1) {
        throw new BadCertTemplateException("biometricInfo extension in request contains empty sequence");
      }

      ASN1EncodableVector vec = new ASN1EncodableVector();

      for (int i = 0; i < n; i++) {
        BiometricData bd = BiometricData.getInstance(seq.getObjectAt(i));
        TypeOfBiometricData bdType = bd.getTypeOfBiometricData();
        if (!biometricInfo.isTypePermitted(bdType)) {
          throw new BadCertTemplateException("biometricInfo[" + i + "].typeOfBiometricData is not permitted");
        }

        HashAlgo hashAlgo;
        try {
          hashAlgo = HashAlgo.getInstance(bd.getHashAlgorithm());
        } catch (NoSuchAlgorithmException ex) {
          throw new CertprofileException("biometricInfo[" + i + "].hashAlgorithm: " + ex.getMessage());
        }

        if (!biometricInfo.isHashAlgorithmPermitted(hashAlgo)) {
          throw new BadCertTemplateException("biometricInfo[" + i + "].hashAlgorithm is not permitted");
        }

        int expHashValueSize = hashAlgo.getLength();
        byte[] hashValue = bd.getBiometricDataHash().getOctets();
        if (hashValue.length != expHashValueSize) {
          throw new BadCertTemplateException("biometricInfo[" + i + "].biometricDataHash has incorrect length");
        }

        ASN1IA5String sourceDataUri = bd.getSourceDataUriIA5();
        TripleState occurrence = biometricInfo.getSourceDataUriOccurrence();
        if (occurrence == TripleState.forbidden) {
          sourceDataUri = null;
        } else if (occurrence == TripleState.required) {
          if (sourceDataUri == null) {
            throw new BadCertTemplateException("biometricInfo[" + i
                + "].sourceDataUri is not specified in request but is required");
          }
        }

        BiometricData newBiometricData = new BiometricData(bdType, hashAlgo.getAlgorithmIdentifier(),
            new DEROctetString(hashValue), sourceDataUri);
        vec.add(newBiometricData);
      }

      ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(), new DERSequence(vec));
      values.addExtension(type, extValue);
      occurrences.remove(type);
    }

    // TlsFeature
    type = Extn.id_pe_tlsfeature;
    ExtensionValue tlsFeature = extensions.getTlsFeature();
    if (tlsFeature != null) {
      if (occurrences.remove(type)) {
        values.addExtension(type, tlsFeature);
      }
    }

    // SMIME
    type = Extn.id_smimeCapabilities;
    ExtensionValue smimeCapabilities = extensions.getSmimeCapabilities();
    if (smimeCapabilities != null) {
      if (occurrences.remove(type)) {
        values.addExtension(type, smimeCapabilities);
      }
    }

    // constant extensions
    Map<ASN1ObjectIdentifier, ExtensionValue> constantExtensions = extensions.getConstantExtensions();
    if (constantExtensions != null) {
      for (Entry<ASN1ObjectIdentifier, ExtensionValue> entry : constantExtensions.entrySet()) {
        ASN1ObjectIdentifier m = entry.getKey();
        if (!occurrences.remove(m)) {
          continue;
        }

        ExtensionValue extensionValue = entry.getValue();
        if (extensionValue != null) {
          values.addExtension(m, extensionValue);
        }
      }
    }

    return values;
  } // method getExtensions

  @Override
  public Set<KeyUsageControl> getKeyUsage() {
    return extensions.getKeyusages();
  }

  @Override
  public Set<ExtKeyUsageControl> getExtendedKeyUsages() {
    return extensions.getExtendedKeyusages();
  }

  @Override
  public CertLevel getCertLevel() {
    return certLevel;
  }

  @Override
  public CertDomain getCertDomain() {
    return certDomain;
  }

  @Override
  public KeypairGenControl getKeypairGenControl() {
    return keypairGenControl;
  }

  @Override
  public String getSerialNumberMode() {
    return serialNumberMode;
  }

  @Override
  public Integer getPathLenBasicConstraint() {
    return extensions.getPathLen();
  }

  @Override
  public AuthorityInfoAccessControl getAiaControl() {
    return extensions.getAiaControl();
  }

  @Override
  public CrlDistributionPointsControl getCrlDpControl() {
    return extensions.getCrlDpControl();
  }

  @Override
  public CrlDistributionPointsControl getFreshestCrlControl() {
    return extensions.getFreshestCrlControl();
  }

  @Override
  public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls() {
    return extensions.getExtensionControls();
  }

  @Override
  public int getMaxCertSize() {
    return (maxSize == null) ? super.getMaxCertSize() : maxSize;
  }

  @Override
  public boolean useIssuerAndSerialInAki() {
    return extensions.isUseIssuerAndSerialInAki();
  }

  @Override
  protected SubjectKeyIdentifierControl getSubjectKeyIdentifierControl() {
    return extensions.getSubjectKeyIdentifier();
  }

  @Override
  public SubjectControl getSubjectControl() {
    return subjectControl;
  }

  public NotBeforeOption getNotBeforeOption() {
    return notBeforeOption;
  }

  @Override
  public Instant getNotBefore(Instant requestedNotBefore) {
    return notBeforeOption.getNotBefore(requestedNotBefore);
  }

  @Override
  public Map<ASN1ObjectIdentifier, KeyParametersOption> getKeyAlgorithms() {
    return keyAlgorithms;
  }

  @Override
  public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> getSubjectInfoAccessModes() {
    return extensions.getSubjectInfoAccessModes();
  }

  @Override
  public X509CertVersion getVersion() {
    return version;
  }

  public XijsonExtensions extensions() {
    return extensions;
  }

  @Override
  public List<SignAlgo> getSignatureAlgorithms() {
    return signatureAlgorithms;
  }

  @Override
  public Set<GeneralNameMode> getSubjectAltNameModes() {
    return extensions.getSubjectAltNameModes();
  }

  public Integer getMaxSize() {
    return maxSize;
  }

  @Override
  public org.bouncycastle.asn1.x509.CertificatePolicies getCertificatePolicies() {
    return extensions.getCertificatePolicies();
  }

  private static boolean booleanValue(Boolean boolObj, boolean dfltValue) {
    return Objects.requireNonNullElse(boolObj, dfltValue);
  }

}
