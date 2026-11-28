// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.CertificatePolicies;
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
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.ProfileUtil;
import org.xipki.ca.api.profile.ctrl.*;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionValueConf;
import org.xipki.ca.certprofile.xijson.conf.RdnType;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.ca.certprofile.xijsonv1.conf.V1XijsonCertprofileType;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.asn1.ccc.EndpointCertificateExtensionSchema;
import org.xipki.security.asn1.ccc.InstanceCACertificateExtensionSchema;
import org.xipki.security.asn1.ccc.SBxDKisCertificateExtensionSchema;
import org.xipki.security.asn1.rpki.ASIdentifiers;
import org.xipki.security.asn1.rpki.IPAddrBlocks;
import org.xipki.security.asn1.stir.TNAuthorizationList;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.TripleState;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.type.SubjectKeyIdentifierControl;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.misc.StringUtil;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Vector;

/**
 * XiJSON certificate profile definition.
 *
 * @author Lijun Liao (xipki)
 */
public class XijsonCertprofile extends Certprofile {

  private static final Logger LOG = LoggerFactory.getLogger(XijsonCertprofile.class);

  private CertDomain certDomain;

  private CertLevel certLevel;

  private KeypairGenControl keypairGenControl;

  private PublicKeyControl publicKeyControl;

  private Integer maxSize;

  private NotBeforeOption notBeforeOption;

  private List<SignAlgo> signatureAlgorithms;

  private SubjectControl subjectControl;

  private Validity validity;

  private boolean hasNoWellDefinedExpirationDate;

  private ValidityMode notAfterMode;

  private XijsonExtensions extensions;

  private void reset() {
    certDomain = null;
    certLevel = null;
    keypairGenControl = null;
    publicKeyControl = null;
    maxSize = null;
    signatureAlgorithms = null;
    notBeforeOption = null;
    subjectControl = null;
    validity = null;
    hasNoWellDefinedExpirationDate = false;
    notAfterMode = null;
    extensions = null;
    extraReset();
  } // method reset

  public XijsonCertprofile() {
  }

  protected void extraReset() {
  }

  @Override
  public PublicKeyControl publicKeyControl() {
    return publicKeyControl;
  }

  @Override
  public Set<KeySingleUsage> keyUsage(KeySpec keySpec) {
    return extensions.getKeyUsage(keySpec);
  }

  @Override
  public void initialize(String data) throws CertprofileException {
    byte[] bytes = StringUtil.toUtf8Bytes(Args.notBlank(data, "data"));

    XijsonCertprofileType conf;
    try {
      JsonMap json = JsonParser.parseMap(bytes, true);
      Object subject = json.getObject("subject");
      if (subject instanceof JsonList) { // V2
        conf = XijsonCertprofileType.parse(json);
      } else { // V1
        conf = V1XijsonCertprofileType.parse(json).toV2();
      }
    } catch (CodecException | RuntimeException ex) {
      LogUtil.error(LOG, ex);
      throw new CertprofileException("caught RuntimeException while parsing certprofile: " +
          ex.getMessage());
    }

    initialize(conf);
  } // method initialize

  public void initialize(XijsonCertprofileType conf) throws CertprofileException {
    Args.notNull(conf, "conf");

    reset();
    try {
      initialize0(conf);
    } catch (RuntimeException ex) {
      LogUtil.error(LOG, ex);
      throw new CertprofileException("caught RuntimeException while initializing certprofile: " +
          ex.getMessage());
    }
  } // method initialize

  private void initialize0(XijsonCertprofileType conf) throws CertprofileException {
    if (conf.signatureAlgorithms() != null) {
      List<SignAlgo> algoNames = conf.signatureAlgorithms();
      if (algoNames.isEmpty()) {
        throw new CertprofileException("none of the signature algorithms is supported: " +
            conf.signatureAlgorithms());
      }

      this.signatureAlgorithms = List.copyOf(algoNames);
    }

    this.maxSize = conf.maxSize();

    if ("99991231235959Z".equalsIgnoreCase(conf.validity())
        || "UNDEFINED".equalsIgnoreCase(conf.validity())) {
      this.hasNoWellDefinedExpirationDate = true;
      this.validity = null;
    } else {
      this.hasNoWellDefinedExpirationDate = false;
      this.validity = Validity.getInstance(conf.validity());
    }
    this.notAfterMode = conf.notAfterMode();
    this.certLevel = conf.certLevel();
    if (this.certLevel == null) {
      throw new CertprofileException("invalid CertLevel");
    }

    this.certDomain = conf.certDomain() == null ? CertDomain.RFC5280 : conf.certDomain();

    // KeypairGenControl
    KeypairGenControl kg = conf.keypairGeneration();
    this.keypairGenControl = (kg == null) ? KeypairGenControl.FORBIDDEN : kg;

    String str = conf.notBeforeTime().toLowerCase().trim();
    Long offsetSeconds = null;
    ZoneId midnightTimeZone = null;
    if (str.startsWith("midnight")) {
      int seperatorIdx = str.indexOf(':');
      String timezoneId = (seperatorIdx == -1) ? "GMT+0"
          : str.substring(seperatorIdx + 1).toUpperCase();
      final List<String> validIds = new ArrayList<>();
      for (int i = 0; i <= 12; i++) {
        validIds.add("GMT+" + i);
        validIds.add("GMT-" + i);
      }

      if (!validIds.contains(timezoneId)) {
        throw new CertprofileException("invalid time zone id " + timezoneId);
      }

      midnightTimeZone = ZoneId.of(timezoneId);
    } else if ("current".equalsIgnoreCase(str)) {
      offsetSeconds = 0L;
    } else if (str.length() > 1) {
      char c0 = str.charAt(0);

      boolean negative = '-' == c0;
      char suffix = str.charAt(str.length() - 1);
      final long unitSeconds;
      if (suffix == 'd') {
        unitSeconds = 24L * 60 * 60;
      } else if (suffix == 'h') {
        unitSeconds = 60L * 60;
      } else if (suffix == 'm') {
        unitSeconds = 60L;
      } else if (suffix == 's') {
        unitSeconds = 1L;
      } else {
        throw new CertprofileException("invalid notBefore " + str);
      }

      String digitStr = str.substring((c0 == '+' || c0 == '-') ? 1 : 0, str.length() - 1);
      if (!StringUtil.isNumber(digitStr)) {
        throw new CertprofileException("invalid notBefore '" + str + "'");
      }

      offsetSeconds = Long.parseLong(digitStr) * unitSeconds;
      if (negative) {
        offsetSeconds *= -1;
      }
    } else {
      throw new CertprofileException("invalid notBefore '" + str + "'");
    }

    notBeforeOption = (offsetSeconds != null)
        ? NotBeforeOption.getOffsetOption(offsetSeconds)
        : NotBeforeOption.getMidNightOption(midnightTimeZone);

    // KeyAlgorithms
    this.publicKeyControl = new PublicKeyControl(conf.keyAlgorithms());

    // Subject
    List<RdnControl> subjectDnControls = new LinkedList<>();
    for (RdnType rdn : conf.subject()) {
      subjectDnControls.add(rdn.toRdnControl());
    }

    Boolean b = conf.keepSubjectOrder();
    this.subjectControl = new SubjectControl(subjectDnControls, b != null && b);

    // Extensions
    this.extensions = new XijsonExtensions(this, conf, subjectControl);
  } // method initialize0

  @Override
  public boolean hasNoWellDefinedExpirationDate() {
    return this.hasNoWellDefinedExpirationDate;
  }

  @Override
  public Validity validity() {
    return validity;
  }

  @Override
  public ValidityMode notAfterMode() {
    return notAfterMode != null ? notAfterMode : super.notAfterMode();
  }

  @Override
  protected void verifySubjectDnOccurrence(X500Name requestedSubject)
      throws BadCertTemplateException {
    Args.notNull(requestedSubject, "requestedSubject");
    ASN1ObjectIdentifier[] types = requestedSubject.getAttributeTypes();

    for (ASN1ObjectIdentifier type : types) {
      RdnControl control = subjectControl.getControl(type);
      if (control == null) {
        throw new BadCertTemplateException(String.format(
            "subject DN of type %s is not allowed", OIDs.oidToDisplayName(type)));
      }

      if (control.value() != null) {
        throw new BadCertTemplateException(String.format(
            "subject DN of type %s is not allowed in the request", OIDs.oidToDisplayName(type)));
      }

      RDN[] rdns = requestedSubject.getRDNs(type);
      int numRdns = (rdns == null) ? 0 : rdns.length;

      if (control.toSAN() == null) {
        if (numRdns > control.maxOccurs() || numRdns < control.minOccurs()) {
          throw new BadCertTemplateException(String.format(
              "occurrence of subject DN of type %s not within the allowed range. " +
              "%d is not within [%d, %d]",
              OIDs.oidToDisplayName(type), numRdns, control.minOccurs(), control.maxOccurs()));
        }
      }
    }

    for (ASN1ObjectIdentifier m : subjectControl.types()) {
      RdnControl occurrence = subjectControl.getControl(m);
      if (occurrence.value() != null) {
        continue;
      }

      if (occurrence.minOccurs() == 0) {
        continue;
      }

      boolean present = false;
      for (ASN1ObjectIdentifier type : types) {
        if (occurrence.type().equals(type)) {
          present = true;
          break;
        }
      }

      if (!present) {
        throw new BadCertTemplateException(String.format(
            "required subject DN of type %s is not present",
            OIDs.oidToDisplayName(occurrence.type())));
      }
    }
  } // method verifySubjectDnOccurrence

  private boolean isCritical(ASN1ObjectIdentifier type) {
    ExtensionControl control = extensionsControl().getControl(type);
    return control != null && control.isCritical();
  }

  @Override
  public ExtensionValues getExtensions(
      List<ASN1ObjectIdentifier> extensionsToProcess,
      X500Name requestedSubject, X500Name grantedSubject,
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Instant notBefore, Instant notAfter, PublicCaInfo caInfo)
      throws CertprofileException, BadCertTemplateException {
    ExtensionValues values = new ExtensionValues();
    if (CollectionUtil.isEmpty(extensionsToProcess)) {
      return values;
    }

    List<ASN1ObjectIdentifier> tmpExtnTypes = new ArrayList<>(extensionsToProcess);
    Args.notNull(requestedSubject, "requestedSubject");
    Args.notNull(notBefore, "notBefore");
    Args.notNull(notAfter, "notAfter");

    // AuthorityKeyIdentifier
    // processed by the CA

    // SubjectKeyIdentifier
    // processed by the CA

    // KeyUsage
    // processed by the CA

    // CertificatePolicies
    // processed by the CA

    // Policy Mappings
    ASN1ObjectIdentifier type = OIDs.Extn.policyMappings;
    ExtensionValue policyMappings = extensions.policyMappings();
    if (policyMappings != null) {
      if (tmpExtnTypes.remove(type)) {
        values.addExtension(type, policyMappings);
      }
    }

    // SubjectAltName
    type = OIDs.Extn.subjectAlternativeName;
    if (tmpExtnTypes.contains(type)) {
      Extension extn = requestedExtensions.get(OIDs.Extn.subjectAlternativeName);
      GeneralNames sanExtnValue = (extn == null) ? null
          : GeneralNames.getInstance(extn.getParsedValue());

      GeneralNames genNames =
          XijsonExtensions.createRequestedSubjectAltNames(
              requestedSubject, sanExtnValue, subjectAltNameModes(),
              extensions.subjectToSubjectAltNameModes(),
              extensions.subjectAltNameOtherNameTypes());

      if (genNames != null) {
        ExtensionValue value = new ExtensionValue(isCritical(type), genNames);
        values.addExtension(type, value);
        tmpExtnTypes.remove(type);
      }
    }

    // IssuerAltName
    // processed by the CA

    // Basic Constraints
    // processed by the CA

    // Name Constraints
    type = OIDs.Extn.nameConstraints;
    ExtensionValue nameConstraints = extensions.nameConstraints();
    if (nameConstraints != null) {
      if (tmpExtnTypes.remove(type)) {
        values.addExtension(type, nameConstraints);
      }
    }

    // PolicyConstrains
    type = OIDs.Extn.policyConstraints;
    ExtensionValue policyConstraints = extensions.policyConstraints();
    if (policyConstraints != null) {
      if (tmpExtnTypes.remove(type)) {
        values.addExtension(type, policyConstraints);
      }
    }

    // ExtendedKeyUsage
    // processed by CA

    // CRL Distribution Points
    // processed by the CA

    // Inhibit anyPolicy
    type = OIDs.Extn.inhibitAnyPolicy;
    ExtensionValue inhibitAnyPolicy = extensions.inhibitAnyPolicy();
    if (inhibitAnyPolicy != null) {
      if (tmpExtnTypes.remove(type)) {
        values.addExtension(type, inhibitAnyPolicy);
      }
    }

    // Freshest CRL
    // processed by the CA

    // Authority Information Access
    // processed by the CA

    // Subject Information Access
    // processed by the CA

    // OCSP NoCheck
    // processed by the CA

    // PrivateKeyUsagePeriod
    type = OIDs.Extn.privateKeyUsagePeriod;
    if (tmpExtnTypes.contains(type)) {
      Instant tmpNotAfter;
      Validity privateKeyUsagePeriod = extensions.privateKeyUsagePeriod();
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
      ExtensionValue extValue = new ExtensionValue(isCritical(type), new DERSequence(vec));
      values.addExtension(type, extValue);
      tmpExtnTypes.remove(type);
    }

    // SubjectDirectoryAttributes
    type = OIDs.Extn.subjectDirectoryAttributes;
    if (tmpExtnTypes.contains(type)) {
      ASN1Encodable extnValue = validateSubjectDirectoryAttributes(requestedExtensions);
      values.addExtension(type, new ExtensionValue(isCritical(type), extnValue));
      tmpExtnTypes.remove(type);
    }

    // QCStatements
    type = OIDs.Extn.qCStatements;
    ExtensionValue qcStatements = extensions.qcStatements();
    List<QcStatementOption> qcStatementsOption = extensions.qcStatementsOption();
    if (tmpExtnTypes.contains(type) && (qcStatements != null || qcStatementsOption != null)) {
      if (qcStatements != null) {
        values.addExtension(type, qcStatements);
        tmpExtnTypes.remove(type);
      } else if (requestedExtensions != null) {
        // extract the data from request
        Extension extension = requestedExtensions.get(type);
        if (extension == null) {
          throw new BadCertTemplateException("No QCStatement extension is in the request");
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(extension.getParsedValue());

        Map<String, int[]> qcEuLimits = new HashMap<>();
        final int n = seq.size();
        for (int i = 0; i < n; i++) {
          QCStatement stmt = QCStatement.getInstance(seq.getObjectAt(i));
          if (!OIDs.QCS.id_etsi_qcs_QcLimitValue.equals(stmt.getStatementId())) {
            continue;
          }

          MonetaryValue monetaryValue = MonetaryValue.getInstance(stmt.getStatementInfo());
          int amount = monetaryValue.getAmount().intValue();
          int exponent = monetaryValue.getExponent().intValue();
          Iso4217CurrencyCode currency = monetaryValue.getCurrency();
          String currencyS = currency.isAlphabetic()
              ? currency.getAlphabetic().toUpperCase()
              : Integer.toString(currency.getNumeric());
          qcEuLimits.put(currencyS, new int[]{amount, exponent});
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (QcStatementOption m : qcStatementsOption) {
          if (m.statement() != null) {
            vec.add(m.statement());
            continue;
          }

          MonetaryValueOption monetaryOption = m.monetaryValueOption();
          String currencyS = monetaryOption.currencyString();
          int[] limit = qcEuLimits.get(currencyS);
          if (limit == null) {
            throw new BadCertTemplateException(
                "no EuLimitValue is specified for currency '" + currencyS + "'");
          }

          int amount = limit[0];
          ExtensionValueConf.Range2Type range = monetaryOption.amountRange();
          if (amount < range.min() || amount > range.max()) {
            throw new BadCertTemplateException("amount for currency '" +
                currencyS + "' is not within [" + range.min() + ", " + range.max() + "]");
          }

          int exponent = limit[1];
          range = monetaryOption.exponentRange();
          if (exponent < range.min() || exponent > range.max()) {
            throw new BadCertTemplateException("exponent for currency '" +
                currencyS + "' is not within [" + range.min() + ", " + range.max() + "]");
          }

          MonetaryValue monetaryVale =
              new MonetaryValue(monetaryOption.currency(), amount, exponent);
          vec.add(new QCStatement(m.statementId(), monetaryVale));
        }

        ExtensionValue extValue = new ExtensionValue(isCritical(type), new DERSequence(vec));
        values.addExtension(type, extValue);
        tmpExtnTypes.remove(type);
      }
    }

    // BiometricData
    type = OIDs.Extn.biometricInfo;
    Extension extension = (requestedExtensions == null) ? null : requestedExtensions.get(type);
    ExtensionValueConf.BiometricInfo biometricInfo = extensions.biometricInfo();
    if (tmpExtnTypes.contains(type) && biometricInfo != null && extension != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(extension.getParsedValue());
      final int n = seq.size();
      if (n < 1) {
        throw new BadCertTemplateException(
            "biometricInfo extension in request contains empty sequence");
      }

      ASN1EncodableVector vec = new ASN1EncodableVector();

      for (int i = 0; i < n; i++) {
        BiometricData bd = BiometricData.getInstance(seq.getObjectAt(i));
        TypeOfBiometricData bdType = bd.getTypeOfBiometricData();

        boolean typePermitted = bdType.isPredefined()
            && biometricInfo.allowsType(bdType.getPredefinedBiometricType());

        if (!typePermitted) {
          throw new BadCertTemplateException("biometricInfo[" + i +
              "].typeOfBiometricData is not permitted");
        }

        HashAlgo hashAlgo;
        try {
          hashAlgo = HashAlgo.getInstance(bd.getHashAlgorithm());
        } catch (NoSuchAlgorithmException ex) {
          throw new CertprofileException("biometricInfo[" + i + "].hashAlgorithm: " +
              ex.getMessage());
        }

        if (!biometricInfo.allowsHashAlgo(hashAlgo)) {
          throw new BadCertTemplateException("biometricInfo[" + i +
              "].hashAlgorithm is not permitted");
        }

        int expHashValueSize = hashAlgo.length();
        byte[] hashValue = Asn1Util.getOctetStringOctets(bd.getBiometricDataHash());
        if (hashValue.length != expHashValueSize) {
          throw new BadCertTemplateException("biometricInfo[" + i +
              "].biometricDataHash has incorrect length");
        }

        ASN1IA5String ia5 = bd.getSourceDataUriIA5();
        String sourceDataUri = (ia5 == null) ? null : ia5.getString();

        TripleState occurrence = biometricInfo.includeSourceDataUri();
        if (occurrence == TripleState.forbidden) {
          sourceDataUri = null;
        } else if (occurrence == TripleState.required) {
          if (sourceDataUri == null) {
            throw new BadCertTemplateException("biometricInfo[" + i +
                "].sourceDataUri is not specified in request but is required");
          }
        }

        BiometricData newBiometricData = new BiometricData(
            bdType, hashAlgo.algorithmIdentifier(), new DEROctetString(hashValue),
            sourceDataUri == null ? null : new DERIA5String(sourceDataUri));

        vec.add(newBiometricData);
      }

      ExtensionValue extValue = new ExtensionValue(isCritical(type), new DERSequence(vec));
      values.addExtension(type, extValue);
      tmpExtnTypes.remove(type);
    }

    // TlsFeature
    type = OIDs.Extn.id_pe_tlsfeature;
    ExtensionValue tlsFeature = extensions.tlsFeature();
    if (tlsFeature != null) {
      if (tmpExtnTypes.remove(type)) {
        values.addExtension(type, tlsFeature);
      }
    }

    // SMIME
    type = OIDs.Extn.id_smimeCapabilities;
    ExtensionValue smimeCapabilities = extensions.smimeCapabilities();
    if (smimeCapabilities != null) {
      if (tmpExtnTypes.remove(type)) {
        values.addExtension(type, smimeCapabilities);
      }
    }

    // CCC
    type = extensions.cccExtensionSchemaType();
    if (type != null && tmpExtnTypes.remove(type)) {
      if (extensions.cccSimpleExtensionSchemaValue() != null) {
        values.addExtension(type, extensions.cccSimpleExtensionSchemaValue());
      } else if (type.equals(OIDs.Extn.id_ccc_E_Instance_CA_Cert)
          || type.equals(OIDs.Extn.id_ccc_H_Endpoint_Cert)
          || type.equals(OIDs.Extn.id_ccc_T_SBxDKis_Endpoint_Cert)){
        ASN1Encodable asn1ExtnValue = null;
        if (requestedExtensions != null) {
          extension = requestedExtensions.get(type);
          if (extension != null) {
            asn1ExtnValue = extension.getParsedValue();
          }
        }

        if (asn1ExtnValue == null) {
          throw new BadCertTemplateException("no extension value is provided in the request for "
              + type.getId());
        }

        ASN1Encodable ccc;
        try {
          if (type.equals(OIDs.Extn.id_ccc_E_Instance_CA_Cert)) {
            ccc = InstanceCACertificateExtensionSchema.getInstance(asn1ExtnValue);
          } else if (type.equals(OIDs.Extn.id_ccc_H_Endpoint_Cert)){
            ccc = EndpointCertificateExtensionSchema.getInstance(asn1ExtnValue);
          } else {
            ccc = SBxDKisCertificateExtensionSchema.getInstance(asn1ExtnValue);
          }
        } catch (Exception e) {
          throw new BadCertTemplateException("invalid extension value provided in the request for "
              + type.getId() + ": " + e.getMessage(), e);
        }

        values.addExtension(type, new ExtensionValue(true, ccc));
      }
    }

    // Microsoft Certificate Template Name
    type = OIDs.Extn.id_microsoft_CertificateTemplateName;
    ExtensionValue msTemplateName = extensions.microsoftCertTemplateName();
    if (msTemplateName != null) {
      if (tmpExtnTypes.remove(type)) {
        values.addExtension(type, msTemplateName);
      }
    }

    // Microsoft Certificate Template Information
    type = OIDs.Extn.id_microsoft_CertificateTemplateInformation;
    ExtensionValue msTemplateInformation = extensions.microsoftCertTemplateInformation();
    if (msTemplateInformation != null) {
      if (tmpExtnTypes.remove(type)) {
        values.addExtension(type, msTemplateInformation);
      }
    }

    // Microsoft Security Identifier
    type = OIDs.Extn.id_microsoft_SID;
    ExtensionValueConf.MicrosoftSID microsoftSID = extensions.microsoftSID();
    if (tmpExtnTypes.contains(type) && requestedExtensions != null) {
      Extension extn = requestedExtensions.get(type);
      if (extn != null) {
        ASN1Encodable extnValue = microsoftSID.checkExtensionValue(extn.getParsedValue());
        ExtensionValue value = new ExtensionValue(isCritical(type), extnValue);
        values.addExtension(type, value);
        tmpExtnTypes.remove(type);
      }
    }

    // SPDM Cert OIDs
    type = OIDs.Extn.id_dmtf_spdm_extension;
    if (tmpExtnTypes.contains(type)) {
      ExtensionValue spdm = extensions.spdmCertOids();
      if (spdm != null) {
        values.addExtension(type, spdm);
        tmpExtnTypes.remove(type);
      }
    }

    // STIR
    type = OIDs.Extn.id_pe_JWTClaimConstraints;
    if (tmpExtnTypes.contains(type)) {
      ExtensionValue stir = extensions.stirJWTClaimPermittedValues();
      if (stir != null) {
        values.addExtension(type, stir);
        tmpExtnTypes.remove(type);
      }
    }

    type = OIDs.Extn.id_pe_TNAuthList;
    if (tmpExtnTypes.contains(type) && requestedExtensions != null) {
      Extension extn = requestedExtensions.get(type);
      if (extn != null) {
        TNAuthorizationList tnList = TNAuthorizationList.getInstance(extn.getParsedValue());
        ExtensionValue value = new ExtensionValue(isCritical(type), tnList);
        values.addExtension(type, value);
        tmpExtnTypes.remove(type);
      }
    }

    // RPKI
    for (ASN1ObjectIdentifier extnType : new ASN1ObjectIdentifier[]{
        OIDs.Extn.ASIdentifiers, OIDs.Extn.ASIdentifiersV2}) {
      type = extnType;
      if (tmpExtnTypes.contains(type) && requestedExtensions != null) {
        Extension extn = requestedExtensions.get(type);
        if (extn != null) {
          ASIdentifiers asIds = ASIdentifiers.getInstance(extn.getParsedValue());
          ExtensionValue value = new ExtensionValue(isCritical(type), asIds);
          values.addExtension(type, value);
          tmpExtnTypes.remove(type);
        }
      }
    }

    // RFC9608
    type = ExtensionID.noRevAvail.oid();
    if (tmpExtnTypes.remove(type)) {
      values.addExtension(type, new ExtensionValue(isCritical(type), DERNull.INSTANCE));
    }

    // BRSKI (RFC8995)
    type = ExtensionID.masaUrl.oid();
    if (tmpExtnTypes.remove(type)) {
      ExtensionValue extnValue;
      if (extensions.masaUrl() != null) {
        extnValue = extensions.masaUrl();
      } else {
        String url = null;
        if (requestedExtensions != null) {
          Extension extn = requestedExtensions.get(type);
          if (extn != null) {
            url = Asn1Util.getIA5String(extn.getParsedValue());
          }
        }

        if (url == null) {
          throw new BadCertTemplateException("no masa url is specified in the requested extension");
        }

        extnValue = new ExtensionValue(isCritical(type), new DERIA5String(url));
      }

      values.addExtension(type, extnValue);
    }

    // ICAO MRTD
    type = ExtensionID.MRTD_NameChange.oid();
    if (tmpExtnTypes.remove(type)) {
      values.addExtension(type, new ExtensionValue(isCritical(type), DERNull.INSTANCE));
    }

    type = ExtensionID.MRTD_DocumentTypeList.oid();
    if (tmpExtnTypes.remove(type)) {
      values.addExtension(type, extensions.mrtdDocumentTypes());
    }

    // RPKI
    for (ASN1ObjectIdentifier extnType : new ASN1ObjectIdentifier[]{
        OIDs.Extn.IPAddrBlocks, OIDs.Extn.IPAddrBlocksV2}) {
      type = extnType;
      if (tmpExtnTypes.contains(type) && requestedExtensions != null) {
        Extension extn = requestedExtensions.get(type);
        if (extn != null) {
          IPAddrBlocks asIds = IPAddrBlocks.getInstance(extn.getParsedValue());
          ExtensionValue value = new ExtensionValue(isCritical(type), asIds);
          values.addExtension(type, value);
          tmpExtnTypes.remove(type);
        }
      }
    }

    // TCG DICE
    type = ExtensionID.dice_ueid.oid();
    if (tmpExtnTypes.remove(type)) {
      Extension extn = requestedExtensions == null ? null : requestedExtensions.get(type);
      if (extn == null) {
        throw new BadCertTemplateException(OIDs.oidToDisplayName(type) +
            ": request extension is not a present");
      }

      if (!(extn.getParsedValue() instanceof ASN1OctetString)) {
        throw new BadCertTemplateException(OIDs.oidToDisplayName(type) +
            ": request extension value is not an OCTET STRING");
      }

      values.addExtension(type, new ExtensionValue(isCritical(type), extn.getParsedValue()));
    }

    // GM/T 0015 extensions
    ASN1ObjectIdentifier[] gmtTypes = {
        OIDs.Extn.id_cn_residentIdCardNumber,
        OIDs.Extn.id_cn_passportNumber,
        OIDs.Extn.id_cn_socialInsuranceNumber,
        OIDs.Extn.id_cn_UnifiedSocialCreditCode};
    for (ASN1ObjectIdentifier gmtType : gmtTypes) {
      type = gmtType;
      if (tmpExtnTypes.contains(type) && requestedExtensions != null) {
        Extension extn = requestedExtensions.get(type);
        if (extn != null) {
          ASN1Encodable asn1 = extn.getParsedValue();
          if (!(asn1 instanceof ASN1String)) {
            throw new BadCertTemplateException(
                OIDs.oidToDisplayName(type) + ": request extension value is not a String");
          }

          String str = ((ASN1String) asn1).getString();
          ASN1Encodable extnValue = OIDs.Extn.id_cn_passportNumber.equals(type)
              ? new DERUTF8String(str) : new DERPrintableString(str);
          ExtensionValue value = new ExtensionValue(isCritical(type), extnValue);
          values.addExtension(type, value);
          tmpExtnTypes.remove(type);
        }
      }
    }

    // constant extensions
    Map<ASN1ObjectIdentifier, ExtensionValue> constantExtensions = extensions.constantExtensions();
    if (constantExtensions != null) {
      for (Entry<ASN1ObjectIdentifier, ExtensionValue> entry : constantExtensions.entrySet()) {
        ASN1ObjectIdentifier m = entry.getKey();
        if (!tmpExtnTypes.remove(m)) {
          continue;
        }

        ExtensionValue extensionValue = entry.getValue();
        if (extensionValue != null) {
          values.addExtension(m, extensionValue);
        }
      }
    }

    // extensions processed by a subclass
    if (!tmpExtnTypes.isEmpty()) {
      ExtensionValues extraValues = getExtraExtensions(Collections.unmodifiableList(tmpExtnTypes),
          requestedSubject, grantedSubject, requestedExtensions, notBefore, notAfter, caInfo);
      if (extraValues != null) {
        for (ASN1ObjectIdentifier m : extraValues.getExtensionTypes()) {
          if (tmpExtnTypes.contains(m)) {
            values.addExtension(m, extraValues.getExtensionValue(m));
          }
        }
      }
    }

    return values;
  } // method getExtensions

  /**
   * Initializes an extension which this profile cannot process itself. Subclasses override this
   * method to support their own extensions, and return the values in
   * {@link #getExtraExtensions}.
   *
   * @param extn the configuration of the extension.
   * @return whether the extension is processed by this profile.
   * @throws CertprofileException if the configuration is invalid.
   */
  protected boolean initExtraExtension(ExtensionType extn) throws CertprofileException {
    return false;
  }

  /**
   * Returns the values of the extensions initialized by {@link #initExtraExtension}.
   *
   * @param extensionsToProcess types of the extensions not processed yet, not modifiable.
   * @param requestedSubject requested subject.
   * @param grantedSubject granted subject.
   * @param requestedExtensions requested extensions, may be {@code null}.
   * @param notBefore notBefore of the certificate.
   * @param notAfter notAfter of the certificate.
   * @param caInfo information of the CA.
   * @return the extension values, may be {@code null}.
   * @throws CertprofileException if error occurs.
   * @throws BadCertTemplateException if the request is not permitted.
   */
  protected ExtensionValues getExtraExtensions(
      List<ASN1ObjectIdentifier> extensionsToProcess, X500Name requestedSubject,
      X500Name grantedSubject, Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Instant notBefore, Instant notAfter, PublicCaInfo caInfo)
      throws CertprofileException, BadCertTemplateException {
    return null;
  }

  public Map<ASN1ObjectIdentifier, ExtensionValue> constantExtensions() {
    return extensions.constantExtensions();
  }

  @Override
  public Set<ExtKeyUsageControl> extendedKeyUsages() {
    return extensions.extendedKeyusages();
  }

  @Override
  public CertLevel certLevel() {
    return certLevel;
  }

  @Override
  public CertDomain certDomain() {
    return certDomain;
  }

  @Override
  public KeypairGenControl keypairGenControl() {
    return keypairGenControl;
  }

  @Override
  public Integer pathLenBasicConstraint() {
    return extensions.pathLen();
  }

  @Override
  public AuthorityInfoAccessControl aiaControl() {
    return extensions.aiaControl();
  }

  @Override
  public ExtensionsControl extensionsControl() {
    return extensions.extensionControls();
  }

  @Override
  public int maxCertSize() {
    return (maxSize == null) ? super.maxCertSize() : maxSize;
  }

  @Override
  public SubjectControl subjectControl() {
    return subjectControl;
  }

  public NotBeforeOption notBeforeOption() {
    return notBeforeOption;
  }

  @Override
  public Instant notBefore(Instant requestedNotBefore) {
    return notBeforeOption.getNotBefore(requestedNotBefore);
  }

  @Override
  public Map<ASN1ObjectIdentifier, Set<GeneralNameTag>> subjectInfoAccessModes() {
    return extensions.subjectInfoAccessModes();
  }

  public XijsonExtensions extensions() {
    return extensions;
  }

  @Override
  public List<SignAlgo> signatureAlgorithms() {
    return signatureAlgorithms;
  }

  @Override
  public Set<GeneralNameTag> subjectAltNameModes() {
    return extensions.subjectAltNameModes();
  }

  public Integer maxSize() {
    return maxSize;
  }

  @Override
  public SubjectKeyIdentifierControl subjectKeyIdentifierControl() {
    return extensions.subjectKeyIdentifier();
  }

  @Override
  public CertificatePolicies certificatePolicies() {
    return extensions.certificatePolicies();
  }

  private ASN1Encodable validateSubjectDirectoryAttributes(
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions)
      throws BadCertTemplateException {
    // attrTypes is either null or non-empty
    List<ASN1ObjectIdentifier> attrTypes = extensions.subjectDirectoryAttributes();
    // extract the data from request
    Extension extension = requestedExtensions.get(ExtensionID.subjectDirectoryAttributes.oid());
    if (extension == null) {
      throw new BadCertTemplateException(
          "No SubjectDirectoryAttributes extension is in the request");
    }

    Vector<?> reqAttrs = SubjectDirectoryAttributes.getInstance(
                        extension.getParsedValue()).getAttributes();
    int size = reqAttrs.size();
    List<ASN1ObjectIdentifier> reqAttrTypes = new ArrayList<>(size);
    Map<ASN1ObjectIdentifier, Attribute> reqAttrsMap = new HashMap<>(size);
    for (Object reqAttr : reqAttrs) {
      Attribute attr = Attribute.getInstance(reqAttr);
      ASN1ObjectIdentifier attrType = attr.getAttrType();
      reqAttrTypes.add(attrType);
      reqAttrsMap.put(attrType, attr);
    }

    if (attrTypes != null) {
      for (ASN1ObjectIdentifier reqAttrType : reqAttrTypes) {
        if (!attrTypes.contains(reqAttrType)) {
          throw new BadCertTemplateException("SubjectDirectoryAttributes: " +
              reqAttrType.getId() + " is requested but not permitted");
        }
      }

      for (ASN1ObjectIdentifier attrType : attrTypes) {
        if (!reqAttrTypes.contains(attrType)) {
          throw new BadCertTemplateException("SubjectDirectoryAttributes: " +
              attrType.getId() + " is required but not in the request");
        }
      }
    } else {
      attrTypes = reqAttrTypes;
    }

    List<Attribute> attrsRes = new ArrayList<>(attrTypes.size());
    try {
      for (ASN1ObjectIdentifier attrType : attrTypes) {
        Attribute reqAttr = reqAttrsMap.get(attrType);
        attrsRes.add(ProfileUtil.canonicalizeSubjectDirectoryAttribute(reqAttr));
      }
    } catch (RuntimeException e) {
      throw new BadCertTemplateException("request not correctly encoded", e);
    }

    return new DERSequence(attrsRes.toArray(new ASN1Encodable[0]));
  }

}
