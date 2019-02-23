/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.certprofile.xijson;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
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
import java.util.TimeZone;
import java.util.Vector;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.profile.BaseCertprofile;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.KeypairGenControl;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.api.profile.SubjectDnSpec;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AdditionalInformation;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AdmissionSyntax;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AuthorityInfoAccess;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AuthorityKeyIdentifier;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.AuthorizationTemplate;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.BasicConstraints;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.BiometricInfo;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.CertificatePolicies;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ExtendedKeyUsage;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.KeyUsage;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.NameConstraints;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.PolicyMappings;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.PrivateKeyUsagePeriod;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.QcStatements;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.Restriction;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SmimeCapabilities;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SmimeCapability;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SmimeCapabilityParameter;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SubjectDirectoryAttributs;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SubjectInfoAccess;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.SubjectInfoAccess.Access;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.TlsFeature;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ValidityModel;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.ca.certprofile.xijson.conf.KeypairGenerationType;
import org.xipki.ca.certprofile.xijson.conf.KeypairGenerationType.KeyType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.PdsLocationType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.QcEuLimitValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.QcStatementValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatementType.Range2Type;
import org.xipki.ca.certprofile.xijson.conf.Subject;
import org.xipki.ca.certprofile.xijson.conf.Subject.RdnType;
import org.xipki.ca.certprofile.xijson.conf.SubjectToSubjectAltNameType;
import org.xipki.ca.certprofile.xijson.conf.X509ProfileType;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XijsonCertprofile extends BaseCertprofile {

  private static final Logger LOG = LoggerFactory.getLogger(XijsonCertprofile.class);

  private ExtensionValue additionalInformation;

  private AdmissionSyntaxOption admission;

  private AuthorityInfoAccessControl aiaControl;

  private Map<ASN1ObjectIdentifier, GeneralNameTag> subjectToSubjectAltNameModes;

  private Set<GeneralNameMode> subjectAltNameModes;

  private Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> subjectInfoAccessModes;

  private ExtensionValue authorizationTemplate;

  private BiometricInfoOption biometricInfo;

  private CertLevel certLevel;

  private KeypairGenControl keypairGenControl;

  private ExtensionValue certificatePolicies;

  private Map<ASN1ObjectIdentifier, ExtensionValue> constantExtensions;

  private Set<ExtKeyUsageControl> extendedKeyusages;

  private Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls;

  private boolean includeIssuerAndSerialInAki;

  private boolean incSerialNoIfSubjectExists;

  private ExtensionValue inhibitAnyPolicy;

  private Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms;

  private Set<KeyUsageControl> keyusages;

  private Integer maxSize;

  private ExtensionValue nameConstraints;

  private Integer pathLen;

  private ExtensionValue policyConstraints;

  private ExtensionValue policyMappings;

  private Validity privateKeyUsagePeriod;

  private ExtensionValue qcStatments;

  private List<QcStatementOption> qcStatementsOption;

  private boolean raOnly;

  private ExtensionValue restriction;

  private boolean serialNumberInReqPermitted;

  private NotBeforeOption notBeforeOption;

  private List<String> signatureAlgorithms;

  private ExtensionValue smimeCapabilities;

  private SubjectControl subjectControl;

  private ExtensionValue tlsFeature;

  private Validity validity;

  private X509CertVersion version;

  private ExtensionValue validityModel;

  private SubjectDirectoryAttributesControl subjectDirAttrsControl;

  private void reset() {
    additionalInformation = null;
    admission = null;
    aiaControl = null;
    subjectToSubjectAltNameModes = null;
    subjectAltNameModes = null;
    subjectInfoAccessModes = null;
    authorizationTemplate = null;
    biometricInfo = null;
    certLevel = null;
    keypairGenControl = null;
    certificatePolicies = null;
    constantExtensions = null;
    extendedKeyusages = null;
    extensionControls = null;
    includeIssuerAndSerialInAki = false;
    incSerialNoIfSubjectExists = false;
    inhibitAnyPolicy = null;
    keyAlgorithms = null;
    keyusages = null;
    maxSize = null;
    nameConstraints = null;
    pathLen = null;
    policyConstraints = null;
    policyMappings = null;
    privateKeyUsagePeriod = null;
    qcStatments = null;
    qcStatementsOption = null;
    raOnly = false;
    restriction = null;
    serialNumberInReqPermitted = true;
    signatureAlgorithms = null;
    notBeforeOption = null;
    smimeCapabilities = null;
    subjectControl = null;
    tlsFeature = null;
    validity = null;
    validityModel = null;
    version = null;
    subjectDirAttrsControl = null;
    extraReset();
  } // method reset

  protected void extraReset() {
  }

  @Override
  public void initialize(String data) throws CertprofileException {
    Args.notBlank(data, "data");

    X509ProfileType conf;
    try {
      byte[] bytes = StringUtil.toUtf8Bytes(data);
      conf = X509ProfileType.parse(new ByteArrayInputStream(bytes));
    } catch (RuntimeException ex) {
      LogUtil.error(LOG, ex);
      throw new CertprofileException(
          "caught RuntimeException while parsing certprofile: " + ex.getMessage());
    }

    initialize(conf);

  } // method initialize

  public void initialize(X509ProfileType conf) throws CertprofileException {
    Args.notNull(conf, "conf");

    reset();
    try {
      initialize0(conf);
    } catch (RuntimeException ex) {
      // TODO:
      ex.printStackTrace();
      LogUtil.error(LOG, ex);
      throw new CertprofileException(
          "caught RuntimeException while initializing certprofile: " + ex.getMessage());
    }
  } // method initialize

  private void initialize0(X509ProfileType conf) throws CertprofileException {
    this.version = conf.getVersion();
    if (this.version == null) {
      this.version = X509CertVersion.v3;
    }

    if (conf.getSignatureAlgorithms() != null) {
      List<String> algoNames = conf.getSignatureAlgorithms();
      List<String> list = new ArrayList<>(algoNames.size());
      for (String algoName : algoNames) {
        try {
          list.add(AlgorithmUtil.canonicalizeSignatureAlgo(algoName));
        } catch (NoSuchAlgorithmException ex) {
          throw new CertprofileException(ex.getMessage(), ex);
        }
      }

      this.signatureAlgorithms = Collections.unmodifiableList(list);
    }

    this.raOnly = conf.getRaOnly() == null ? false : conf.getRaOnly();
    this.maxSize = conf.getMaxSize();

    this.validity = Validity.getInstance(conf.getValidity());
    this.certLevel = conf.getCertLevel();
    if (this.certLevel == null) {
      throw new CertprofileException("invalid CertLevel");
    }

    // KeypairGenControl
    KeypairGenerationType kg = conf.getKeypairGeneration();

    if (kg == null || kg.isForbidden()) {
      this.keypairGenControl = KeypairGenControl.ForbiddenKeypairGenControl.INSTANCE;
    } else if (kg.isInheritCA()) {
      this.keypairGenControl = KeypairGenControl.InheritCAKeypairGenControl.INSTANCE;
    } else {
      KeyType keyType = kg.getKeyType();
      ASN1ObjectIdentifier keyAlgOid = new ASN1ObjectIdentifier(kg.getAlgorithm().getOid());
      Map<String, String> params = kg.getParameters();

      if (keyType == KeyType.rsa) {
        int keySize = Integer.parseInt(params.get(KeypairGenerationType.PARAM_keysize));
        BigInteger publicExponent = null;
        String tmp = kg.getParameters().get(KeypairGenerationType.PARAM_publicExponent);
        if (tmp != null) {
          publicExponent = StringUtil.startsWithIgnoreCase(tmp, "0x")
              ? new BigInteger(tmp.substring(2), 16) : new BigInteger(tmp);
        }

        this.keypairGenControl = new KeypairGenControl.RSAKeypairGenControl(
                                    keySize, publicExponent, keyAlgOid);
      } else if (keyType == KeyType.ec) {
        ASN1ObjectIdentifier curveOid =
            new ASN1ObjectIdentifier(params.get(KeypairGenerationType.PARAM_curve));
        this.keypairGenControl = new KeypairGenControl.ECKeypairGenControl(curveOid, keyAlgOid);
      } else if (keyType == KeyType.dsa) {
        int plen = Integer.parseInt(params.get(KeypairGenerationType.PARAM_plength));
        String tmp = params.get(KeypairGenerationType.PARAM_qlength);
        int qlen = tmp == null ? 0 : Integer.parseInt(tmp);
        this.keypairGenControl = new KeypairGenControl.DSAKeypairGenControl(plen, qlen, keyAlgOid);
      } else {
        throw new CertprofileException("unknown KeypairGeneration type " + keyType);
      }
    }

    String str = conf.getNotBeforeTime().toLowerCase().trim();
    Long offsetSeconds = null;
    TimeZone midnightTimeZone = null;
    if (str.startsWith("midnight")) {
      int seperatorIdx = str.indexOf(':');
      String timezoneId = (seperatorIdx == -1)
          ? "GMT+0" : str.substring(seperatorIdx + 1).toUpperCase();
      final List<String> validIds = Arrays.asList(new String[]{
          "GMT+0", "GMT+1", "GMT+2", "GMT+3", "GMT+4", "GMT+5",
          "GMT+6", "GMT+7", "GMT+8", "GMT+09", "GMT+10", "GMT+11", "GMT+12",
          "GMT-0", "GMT-1", "GMT-2", "GMT-3", "GMT-4", "GMT-5",
          "GMT-6", "GMT-7", "GMT-8", "GMT-09", "GMT-10", "GMT-11", "GMT-12"});

      if (!validIds.contains(timezoneId)) {
        throw new CertprofileException("invalid time zone id " + timezoneId);
      }

      midnightTimeZone = TimeZone.getTimeZone(timezoneId);
    } else if ("current".equalsIgnoreCase(str)) {
      offsetSeconds = 0L;
    } else if (str.length() > 2) {
      char sign = str.charAt(0);
      char suffix = str.charAt(str.length() - 1);
      if (sign == '+' || sign == '-') {
        long digit = Long.parseLong(str.substring(1, str.length() - 1));
        long seconds;
        switch (suffix) {
          case 'd':
            seconds = digit * (24L * 60 * 60);
            break;
          case 'h':
            seconds = digit * (60L * 60);
            break;
          case 'm':
            seconds = digit * 60L;
            break;
          case 's':
            seconds = digit;
            break;
          default:
            throw new CertprofileException("invalid notBefore " + str);
        }
        offsetSeconds = (sign == '+') ? seconds : -1 * seconds;
      } else {
        throw new CertprofileException("invalid notBefore '" + str + "'");
      }
    } else {
      throw new CertprofileException("invalid notBefore '" + str + "'");
    }

    if (offsetSeconds != null) {
      this.notBeforeOption = NotBeforeOption.getOffsetOption(offsetSeconds);
    } else {
      this.notBeforeOption = NotBeforeOption.getMidNightOption(midnightTimeZone);
    }

    this.serialNumberInReqPermitted = conf.isSerialNumberInReq();

    // KeyAlgorithms
    this.keyAlgorithms = conf.toXiKeyAlgorithms();

    // Subject
    Subject subject = conf.getSubject();
    List<RdnControl> subjectDnControls = new LinkedList<>();

    for (RdnType rdn : subject.getRdns()) {
      ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(rdn.getType().getOid());

      Range range = (rdn.getMinLen() != null || rdn.getMaxLen() != null)
          ? new Range(rdn.getMinLen(), rdn.getMaxLen()) :  null;

      RdnControl rdnControl = new RdnControl(type, rdn.getMinOccurs(), rdn.getMaxOccurs());
      subjectDnControls.add(rdnControl);

      rdnControl.setStringType(rdn.getStringType());
      rdnControl.setStringLengthRange(range);
      if (rdn.getRegex() != null) {
        rdnControl.setPattern(Pattern.compile(rdn.getRegex()));
      }
      rdnControl.setPrefix(rdn.getPrefix());
      rdnControl.setSuffix(rdn.getSuffix());
      rdnControl.setGroup(rdn.getGroup());
      SubjectDnSpec.fixRdnControl(rdnControl);
    }

    this.subjectControl = new SubjectControl(subjectDnControls, subject.isKeepRdnOrder());
    this.incSerialNoIfSubjectExists = subject.isIncSerialNumber();

    // Extensions
    Map<String, ExtensionType> extensions = conf.buildExtensions();

    // Extension controls
    this.extensionControls = conf.buildExtensionControls();
    Set<ASN1ObjectIdentifier> extnIds = new HashSet<>(this.extensionControls.keySet());

    // SubjectToSubjectAltName
    initSubjectToSubjectAltNames(conf.getSubjectToSubjectAltNames());

    // AdditionalInformation
    initAdditionalInformation(extnIds, extensions);

    // Admission
    initAdmission(extnIds, extensions);

    // AuthorityInfoAccess
    initAuthorityInfoAccess(extnIds, extensions);

    // AuthorityKeyIdentifier
    initAuthorityKeyIdentifier(extnIds, extensions);

    // AuthorizationTemplate
    initAuthorizationTemplate(extnIds, extensions);

    // BasicConstrains
    initBasicConstraints(extnIds, extensions);

    // BiometricInfo
    initBiometricInfo(extnIds, extensions);

    // Certificate Policies
    initCertificatePolicies(extnIds, extensions);

    // ExtendedKeyUsage
    initExtendedKeyUsage(extnIds, extensions);

    // Inhibit anyPolicy
    initInhibitAnyPolicy(extnIds, extensions);

    // KeyUsage
    initKeyUsage(extnIds, extensions);

    // Name Constrains
    initNameConstraints(extnIds, extensions);

    // Policy Constraints
    initPolicyConstraints(extnIds, extensions);

    // Policy Mappings
    initPolicyMappings(extnIds, extensions);

    // PrivateKeyUsagePeriod
    initPrivateKeyUsagePeriod(extnIds, extensions);

    // QCStatements
    initQcStatements(extnIds, extensions);

    // Restriction
    initRestriction(extnIds, extensions);

    // SMIMECapatibilities
    initSmimeCapabilities(extnIds, extensions);

    // SubjectAltNameMode
    initSubjectAlternativeName(extnIds, extensions);

    // SubjectInfoAccess
    initSubjectInfoAccess(extnIds, extensions);

    // TlsFeature
    initTlsFeature(extnIds, extensions);

    // validityModel
    initValidityModel(extnIds, extensions);

    // SubjectDirectoryAttributes
    initSubjectDirAttrs(extnIds, extensions);

    // constant extensions
    this.constantExtensions = conf.buildConstantExtesions();
    if (this.constantExtensions != null) {
      extnIds.removeAll(this.constantExtensions.keySet());
    }

    // validate the configuration
    if (subjectToSubjectAltNameModes != null) {
      ASN1ObjectIdentifier type = Extension.subjectAlternativeName;
      if (!extensionControls.containsKey(type)) {
        throw new CertprofileException("subjectToSubjectAltNames cannot be configured if extension"
            + " subjectAltNames is not permitted");
      }

      if (subjectAltNameModes != null) {
        for (ASN1ObjectIdentifier attrType : subjectToSubjectAltNameModes.keySet()) {
          GeneralNameTag nameTag = subjectToSubjectAltNameModes.get(attrType);
          boolean allowed = false;
          for (GeneralNameMode m : subjectAltNameModes) {
            if (m.getTag() == nameTag) {
              allowed = true;
              break;
            }
          }

          if (!allowed) {
            throw new CertprofileException("target SubjectAltName type " + nameTag
                + " is not allowed");
          }
        }
      }
    }

    // Remove the extension processed not be the Certprofile, but by the CA
    extnIds.remove(Extension.issuerAlternativeName);
    extnIds.remove(Extension.authorityInfoAccess);
    extnIds.remove(Extension.cRLDistributionPoints);
    extnIds.remove(Extension.freshestCRL);
    extnIds.remove(Extension.subjectKeyIdentifier);
    extnIds.remove(Extension.subjectInfoAccess);
    extnIds.remove(ObjectIdentifiers.id_extension_pkix_ocsp_nocheck);

    // to avoid race conflict.
    Set<ASN1ObjectIdentifier> copyOfExtnIds = new HashSet<>(extnIds);
    for (ASN1ObjectIdentifier extnId : copyOfExtnIds) {
      ExtensionType extn = getExtension(extnId, extensions);
      boolean processed = initExtraExtension(extn);
      if (processed) {
        extnIds.remove(extnId);
      }
    }

    if (!extnIds.isEmpty()) {
      throw new CertprofileException("Cannot process the extensions: " + extnIds);
    }
  } // method initialize0

  /**
   * Process the extension.
   *
   * @param extnId
   *          ID of the extensions to be processed
   * @param extn
   *          Configuration of the extension
   * @return whether the extension is processed
   */
  protected boolean initExtraExtension(ExtensionType extn) throws CertprofileException {
    return false;
  }

  private void initSubjectToSubjectAltNames(List<SubjectToSubjectAltNameType> list)
      throws CertprofileException {
    if (CollectionUtil.isEmpty(list)) {
      return;
    }

    subjectToSubjectAltNameModes = new HashMap<>();
    for (SubjectToSubjectAltNameType m : list) {
      subjectToSubjectAltNameModes.put(
          new ASN1ObjectIdentifier(m.getSource().getOid()), m.getTarget());
    }
  }

  private void initAdditionalInformation(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_additionalInformation;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      AdditionalInformation extConf = getExtension(type, extensions).getAdditionalInformation();
      if (extConf != null) {
        ASN1Encodable extValue = extConf.getType().createDirectoryString(extConf.getText());
        additionalInformation =
            new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
      }
    }
  }

  private void initAdmission(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_admission;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      AdmissionSyntax extConf = getExtension(type, extensions).getAdmissionSyntax();
      if (extConf != null) {
        this.admission = extConf.toXiAdmissionSyntax(extensionControls.get(type).isCritical());
      }
    }
  }

  private void initAuthorityInfoAccess(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.authorityInfoAccess;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      AuthorityInfoAccess extConf = getExtension(type, extensions).getAuthorityInfoAccess();
      if (extConf != null) {
        this.aiaControl = new AuthorityInfoAccessControl(extConf.isIncludeCaIssuers(),
            extConf.isIncludeOcsp());
      }
    }
  }

  private void initAuthorityKeyIdentifier(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.authorityKeyIdentifier;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      AuthorityKeyIdentifier extConf = getExtension(type, extensions).getAuthorityKeyIdentifier();
      if (extConf != null) {
        this.includeIssuerAndSerialInAki = extConf.isIncludeIssuerAndSerial();
      }
    }
  }

  private void initAuthorizationTemplate(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = ObjectIdentifiers.id_xipki_ext_authorizationTemplate;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      AuthorizationTemplate extConf = getExtension(type, extensions).getAuthorizationTemplate();
      if (extConf != null) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1ObjectIdentifier(extConf.getType().getOid()));
        vec.add(new DEROctetString(extConf.getAccessRights().getValue()));
        ASN1Encodable extValue = new DERSequence(vec);
        authorizationTemplate =
            new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
      }
    }
  }

  private void initBasicConstraints(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.basicConstraints;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      BasicConstraints extConf = getExtension(type, extensions).getBasicConstrains();
      if (extConf != null) {
        this.pathLen = extConf.getPathLen();
      }
    }
  }

  private void initBiometricInfo(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
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
  }

  private void initCertificatePolicies(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.certificatePolicies;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      CertificatePolicies extConf = getExtension(type, extensions).getCertificatePolicies();
      if (extConf != null) {
        org.bouncycastle.asn1.x509.CertificatePolicies value = extConf.toXiCertificatePolicies();
        this.certificatePolicies =
            new ExtensionValue(extensionControls.get(type).isCritical(), value);
      }
    }
  }

  private void initExtendedKeyUsage(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.extendedKeyUsage;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      ExtendedKeyUsage extConf = getExtension(type, extensions).getExtendedKeyUsage();
      if (extConf != null) {
        this.extendedKeyusages = extConf.toXiExtKeyUsageOptions();
      }
    }
  }

  private void initInhibitAnyPolicy(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.inhibitAnyPolicy;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      InhibitAnyPolicy extConf = getExtension(type, extensions).getInhibitAnyPolicy();
      if (extConf != null) {
        int skipCerts = extConf.getSkipCerts();
        if (skipCerts < 0) {
          throw new CertprofileException(
              "negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
        }
        ASN1Integer value = new ASN1Integer(BigInteger.valueOf(skipCerts));
        this.inhibitAnyPolicy = new ExtensionValue(extensionControls.get(type).isCritical(), value);
      }
    }
  }

  private void initKeyUsage(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.keyUsage;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      KeyUsage extConf = getExtension(type, extensions).getKeyUsage();
      if (extConf != null) {
        this.keyusages = extConf.toXiKeyUsageOptions();
      }
    }
  }

  private void initNameConstraints(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.nameConstraints;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      NameConstraints extConf = getExtension(type, extensions).getNameConstraints();
      if (extConf != null) {
        org.bouncycastle.asn1.x509.NameConstraints value = extConf.toXiNameConstrains();
        this.nameConstraints = new ExtensionValue(extensionControls.get(type).isCritical(), value);
      }
    }
  }

  private void initPrivateKeyUsagePeriod(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.privateKeyUsagePeriod;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      PrivateKeyUsagePeriod extConf = getExtension(type, extensions).getPrivateKeyUsagePeriod();
      if (extConf != null) {
        privateKeyUsagePeriod = Validity.getInstance(extConf.getValidity());
      }
    }
  }

  private void initPolicyConstraints(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.policyConstraints;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      PolicyConstraints extConf = getExtension(type, extensions).getPolicyConstraints();
      if (extConf != null) {
        ASN1Sequence value = extConf.toXiPolicyConstrains();
        this.policyConstraints =
            new ExtensionValue(extensionControls.get(type).isCritical(), value);
      }
    }
  }

  private void initPolicyMappings(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.policyMappings;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      PolicyMappings extConf = getExtension(type, extensions).getPolicyMappings();
      if (extConf != null) {
        org.bouncycastle.asn1.x509.PolicyMappings value = extConf.toXiPolicyMappings();
        this.policyMappings = new ExtensionValue(extensionControls.get(type).isCritical(), value);
      }
    }
  }

  private void initQcStatements(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
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
      ASN1ObjectIdentifier qcStatementId = new ASN1ObjectIdentifier(
          m.getStatementId().getOid());
      QcStatementOption qcStatementOption;

      QcStatementValueType statementValue = m.getStatementValue();
      if (statementValue == null) {
        QCStatement qcStatment = new QCStatement(qcStatementId);
        qcStatementOption = new QcStatementOption(qcStatment);
      } else if (statementValue.getQcRetentionPeriod() != null) {
        QCStatement qcStatment = new QCStatement(qcStatementId,
            new ASN1Integer(statementValue.getQcRetentionPeriod()));
        qcStatementOption = new QcStatementOption(qcStatment);
      } else if (statementValue.getConstant() != null) {
        ASN1Encodable constantStatementValue;
        try {
          constantStatementValue = new ASN1StreamParser(
              statementValue.getConstant().getValue()).readObject();
        } catch (IOException ex) {
          throw new CertprofileException("can not parse the constant value of QcStatement");
        }
        QCStatement qcStatment = new QCStatement(qcStatementId, constantStatementValue);
        qcStatementOption = new QcStatementOption(qcStatment);
      } else if (statementValue.getQcEuLimitValue() != null) {
        QcEuLimitValueType euLimitType = statementValue.getQcEuLimitValue();
        String tmpCurrency = euLimitType.getCurrency().toUpperCase();
        if (currencyCodes.contains(tmpCurrency)) {
          throw new CertprofileException("Duplicated definition of qcStatments with QCEuLimitValue"
              + " for the currency " + tmpCurrency);
        }

        Iso4217CurrencyCode currency = StringUtil.isNumber(tmpCurrency)
            ? new Iso4217CurrencyCode(Integer.parseInt(tmpCurrency))
            : new Iso4217CurrencyCode(tmpCurrency);

        Range2Type r1 = euLimitType.getAmount();
        Range2Type r2 = euLimitType.getExponent();
        if (r1.getMin() == r1.getMax() && r2.getMin() == r2.getMax()) {
          MonetaryValue monetaryValue = new MonetaryValue(currency, r1.getMin(), r2.getMin());
          QCStatement qcStatement = new QCStatement(qcStatementId, monetaryValue);
          qcStatementOption = new QcStatementOption(qcStatement);
        } else {
          MonetaryValueOption monetaryValueOption = new MonetaryValueOption(currency, r1, r2);
          qcStatementOption = new QcStatementOption(qcStatementId, monetaryValueOption);
          requireInfoFromReq = true;
        }
        currencyCodes.add(tmpCurrency);
      } else if (statementValue.getPdsLocations() != null) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (PdsLocationType pl : statementValue.getPdsLocations()) {
          ASN1EncodableVector vec2 = new ASN1EncodableVector();
          vec2.add(new DERIA5String(pl.getUrl()));
          String lang = pl.getLanguage();
          if (lang.length() != 2) {
            throw new CertprofileException("invalid language '" + lang + "'");
          }
          vec2.add(new DERPrintableString(lang));
          DERSequence seq = new DERSequence(vec2);
          vec.add(seq);
        }
        QCStatement qcStatement = new QCStatement(qcStatementId, new DERSequence(vec));
        qcStatementOption = new QcStatementOption(qcStatement);
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
    ASN1Sequence seq = new DERSequence(vec);
    qcStatments = new ExtensionValue(extensionControls.get(type).isCritical(), seq);
    qcStatementsOption = null;
  }

  private void initRestriction(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_restriction;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      Restriction extConf = getExtension(type, extensions).getRestriction();
      if (extConf != null) {
        ASN1Encodable extValue = extConf.getType().createDirectoryString(extConf.getText());
        restriction = new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
      }
    }
  }

  private void initSmimeCapabilities(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = ObjectIdentifiers.id_smimeCapabilities;
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
      org.bouncycastle.asn1.smime.SMIMECapability cap =
          new org.bouncycastle.asn1.smime.SMIMECapability(oid, params);
      vec.add(cap);
    }

    ASN1Encodable extValue = new DERSequence(vec);
    smimeCapabilities = new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
  }

  private void initSubjectAlternativeName(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.subjectAlternativeName;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      GeneralNameType extConf = getExtension(type, extensions).getSubjectAltName();
      if (extConf != null) {
        this.subjectAltNameModes = extConf.toGeneralNameModes();
      }
    }
  }

  private void initSubjectInfoAccess(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.subjectInfoAccess;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      SubjectInfoAccess extConf = getExtension(type, extensions).getSubjectInfoAccess();
      if (extConf != null) {
        List<Access> list = extConf.getAccesses();
        this.subjectInfoAccessModes = new HashMap<>();
        for (Access entry : list) {
          this.subjectInfoAccessModes.put(
              new ASN1ObjectIdentifier(entry.getAccessMethod().getOid()),
              entry.getAccessLocation().toGeneralNameModes());
        }
      }
    }
  }

  private void initTlsFeature(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = ObjectIdentifiers.id_pe_tlsfeature;
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
    ASN1Encodable extValue = new DERSequence(vec);
    tlsFeature = new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
  }

  /**
   * See <a href="https://www.hrz.tu-darmstadt.de/itsicherheit/object_identifier/oids_der_informatik__cdc/index.de.jsp#validity_models">Validity Model</a>
   * for details.
   * <pre>
   * SEQUENCE {
   *    validityModelId OBJECT IDENTIFIER,
   *    validityModelInfo ANY DEFINED BY validityModelId OPTIONAL
   *  }
   * </pre>
   */
  private void initValidityModel(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_validityModel;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      ValidityModel extConf = getExtension(type, extensions).getValidityModel();
      if (extConf != null) {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(extConf.getModelId().getOid());
        ASN1Encodable extValue = new DERSequence(oid);
        validityModel = new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
      }
    }
  }

  private void initSubjectDirAttrs(Set<ASN1ObjectIdentifier> extnIds,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ASN1ObjectIdentifier type = Extension.subjectDirectoryAttributes;
    if (extensionControls.containsKey(type)) {
      extnIds.remove(type);
      SubjectDirectoryAttributs extConf =
          getExtension(type, extensions).getSubjectDirectoryAttributs();
      if (extConf != null) {
        List<ASN1ObjectIdentifier> types = toOidList(extConf.getTypes());
        subjectDirAttrsControl = new SubjectDirectoryAttributesControl(types);
      }
    }
  }

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

  @Override
  public Validity getValidity() {
    return validity;
  }

  @Override
  public ExtensionValues getExtensions(
      Map<ASN1ObjectIdentifier, ExtensionControl> extensionOccurences,
      X500Name requestedSubject, X500Name grantedSubject,
      Extensions requestedExtensions, Date notBefore, Date notAfter,
      PublicCaInfo caInfo) throws CertprofileException, BadCertTemplateException {
    ExtensionValues values = new ExtensionValues();
    if (CollectionUtil.isEmpty(extensionOccurences)) {
      return values;
    }

    Args.notNull(requestedSubject, "requestedSubject");
    Args.notNull(notBefore, "notBefore");
    Args.notNull(notAfter, "notAfter");

    Set<ASN1ObjectIdentifier> occurences = new HashSet<>(extensionOccurences.keySet());

    // AuthorityKeyIdentifier
    // processed by the CA

    // SubjectKeyIdentifier
    // processed by the CA

    // KeyUsage
    // processed by the CA

    // CertificatePolicies
    ASN1ObjectIdentifier type = Extension.certificatePolicies;
    if (certificatePolicies != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, certificatePolicies);
      }
    }

    // Policy Mappings
    type = Extension.policyMappings;
    if (policyMappings != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, policyMappings);
      }
    }

    // SubjectAltName
    type = Extension.subjectAlternativeName;
    if (occurences.contains(type)) {
      GeneralNames genNames = createRequestedSubjectAltNames(requestedSubject, grantedSubject,
          requestedExtensions);
      if (genNames != null) {
        ExtensionValue value = new ExtensionValue(extensionControls.get(type).isCritical(),
            genNames);
        values.addExtension(type, value);
        occurences.remove(type);
      }
    }

    // IssuerAltName
    // processed by the CA

    // Subject Directory Attributes
    type = Extension.subjectDirectoryAttributes;
    if (occurences.contains(type) && subjectDirAttrsControl != null) {
      Extension extension = (requestedExtensions == null) ? null
          : requestedExtensions.getExtension(type);
      if (extension == null) {
        throw new BadCertTemplateException(
            "no SubjectDirecotryAttributes extension is contained in the request");
      }

      ASN1GeneralizedTime dateOfBirth = null;
      String placeOfBirth = null;
      String gender = null;
      List<String> countryOfCitizenshipList = new LinkedList<>();
      List<String> countryOfResidenceList = new LinkedList<>();
      Map<ASN1ObjectIdentifier, List<ASN1Encodable>> otherAttrs = new HashMap<>();

      Vector<?> reqSubDirAttrs = SubjectDirectoryAttributes.getInstance(
          extension.getParsedValue()).getAttributes();
      final int n = reqSubDirAttrs.size();
      for (int i = 0; i < n; i++) {
        Attribute attr = (Attribute) reqSubDirAttrs.get(i);
        ASN1ObjectIdentifier attrType = attr.getAttrType();
        ASN1Encodable attrVal = attr.getAttributeValues()[0];

        if (ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(attrType)) {
          dateOfBirth = ASN1GeneralizedTime.getInstance(attrVal);
        } else if (ObjectIdentifiers.DN_PLACE_OF_BIRTH.equals(attrType)) {
          placeOfBirth = DirectoryString.getInstance(attrVal).getString();
        } else if (ObjectIdentifiers.DN_GENDER.equals(attrType)) {
          gender = DERPrintableString.getInstance(attrVal).getString();
        } else if (ObjectIdentifiers.DN_COUNTRY_OF_CITIZENSHIP.equals(attrType)) {
          String country = DERPrintableString.getInstance(attrVal).getString();
          countryOfCitizenshipList.add(country);
        } else if (ObjectIdentifiers.DN_COUNTRY_OF_RESIDENCE.equals(attrType)) {
          String country = DERPrintableString.getInstance(attrVal).getString();
          countryOfResidenceList.add(country);
        } else {
          List<ASN1Encodable> otherAttrVals = otherAttrs.get(attrType);
          if (otherAttrVals == null) {
            otherAttrVals = new LinkedList<>();
            otherAttrs.put(attrType, otherAttrVals);
          }
          otherAttrVals.add(attrVal);
        }
      }

      Vector<Attribute> attrs = new Vector<>();
      for (ASN1ObjectIdentifier attrType : subjectDirAttrsControl.getTypes()) {
        if (ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(attrType)) {
          if (dateOfBirth != null) {
            String timeStirng = dateOfBirth.getTimeString();
            if (!SubjectDnSpec.PATTERN_DATE_OF_BIRTH.matcher(timeStirng).matches()) {
              throw new BadCertTemplateException("invalid dateOfBirth " + timeStirng);
            }
            attrs.add(new Attribute(attrType, new DERSet(dateOfBirth)));
            continue;
          }
        } else if (ObjectIdentifiers.DN_PLACE_OF_BIRTH.equals(attrType)) {
          if (placeOfBirth != null) {
            ASN1Encodable attrVal = new DERUTF8String(placeOfBirth);
            attrs.add(new Attribute(attrType, new DERSet(attrVal)));
            continue;
          }
        } else if (ObjectIdentifiers.DN_GENDER.equals(attrType)) {
          if (gender != null && !gender.isEmpty()) {
            char ch = gender.charAt(0);
            if (!(gender.length() == 1
                && (ch == 'f' || ch == 'F' || ch == 'm' || ch == 'M'))) {
              throw new BadCertTemplateException("invalid gender " + gender);
            }
            ASN1Encodable attrVal = new DERPrintableString(gender);
            attrs.add(new Attribute(attrType, new DERSet(attrVal)));
            continue;
          }
        } else if (ObjectIdentifiers.DN_COUNTRY_OF_CITIZENSHIP.equals(attrType)) {
          if (!countryOfCitizenshipList.isEmpty()) {
            for (String country : countryOfCitizenshipList) {
              if (!SubjectDnSpec.isValidCountryAreaCode(country)) {
                throw new BadCertTemplateException("invalid countryOfCitizenship code " + country);
              }
              ASN1Encodable attrVal = new DERPrintableString(country);
              attrs.add(new Attribute(attrType, new DERSet(attrVal)));
            }
            continue;
          }
        } else if (ObjectIdentifiers.DN_COUNTRY_OF_RESIDENCE.equals(attrType)) {
          if (!countryOfResidenceList.isEmpty()) {
            for (String country : countryOfResidenceList) {
              if (!SubjectDnSpec.isValidCountryAreaCode(country)) {
                throw new BadCertTemplateException("invalid countryOfResidence code " + country);
              }
              ASN1Encodable attrVal = new DERPrintableString(country);
              attrs.add(new Attribute(attrType, new DERSet(attrVal)));
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
      ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(),
          subjDirAttrs);
      values.addExtension(type, extValue);
      occurences.remove(type);
    }

    // Basic Constraints
    // processed by the CA

    // Name Constraints
    type = Extension.nameConstraints;
    if (nameConstraints != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, nameConstraints);
      }
    }

    // PolicyConstrains
    type = Extension.policyConstraints;
    if (policyConstraints != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, policyConstraints);
      }
    }

    // ExtendedKeyUsage
    // processed by CA

    // CRL Distribution Points
    // processed by the CA

    // Inhibit anyPolicy
    type = Extension.inhibitAnyPolicy;
    if (inhibitAnyPolicy != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, inhibitAnyPolicy);
      }
    }

    // Freshest CRL
    // processed by the CA

    // Authority Information Access
    // processed by the CA

    // Subject Information Access
    // processed by the CA

    // Admission
    type = ObjectIdentifiers.id_extension_admission;
    if (occurences.contains(type) && admission != null) {
      if (admission.isInputFromRequestRequired()) {
        Extension extension = (requestedExtensions == null) ? null
            : requestedExtensions.getExtension(type);
        if (extension == null) {
          throw new BadCertTemplateException("No Admission extension is contained in the request");
        }

        Admissions[] reqAdmissions =
            org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax.getInstance(
                extension.getParsedValue()).getContentsOfAdmissions();

        final int n = reqAdmissions.length;
        List<List<String>> reqRegNumsList = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
          Admissions reqAdmission = reqAdmissions[i];
          ProfessionInfo[] reqPis = reqAdmission.getProfessionInfos();
          List<String> reqNums = new ArrayList<>(reqPis.length);
          reqRegNumsList.add(reqNums);
          for (ProfessionInfo reqPi : reqPis) {
            String reqNum = reqPi.getRegistrationNumber();
            reqNums.add(reqNum);
          }
        }
        values.addExtension(type, admission.getExtensionValue(reqRegNumsList));
        occurences.remove(type);
      } else {
        values.addExtension(type, admission.getExtensionValue(null));
        occurences.remove(type);
      }
    }

    // OCSP Nocheck
    // processed by the CA

    // restriction
    type = ObjectIdentifiers.id_extension_restriction;
    if (restriction != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, restriction);
      }
    }

    // AdditionalInformation
    type = ObjectIdentifiers.id_extension_additionalInformation;
    if (additionalInformation != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, additionalInformation);
      }
    }

    // ValidityModel
    type = ObjectIdentifiers.id_extension_validityModel;
    if (validityModel != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, validityModel);
      }
    }

    // PrivateKeyUsagePeriod
    type = Extension.privateKeyUsagePeriod;
    if (occurences.contains(type)) {
      Date tmpNotAfter;
      if (privateKeyUsagePeriod == null) {
        tmpNotAfter = notAfter;
      } else {
        tmpNotAfter = privateKeyUsagePeriod.add(notBefore);
        if (tmpNotAfter.after(notAfter)) {
          tmpNotAfter = notAfter;
        }
      }

      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new DERTaggedObject(false, 0, new DERGeneralizedTime(notBefore)));
      vec.add(new DERTaggedObject(false, 1, new DERGeneralizedTime(tmpNotAfter)));
      ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(),
          new DERSequence(vec));
      values.addExtension(type, extValue);
      occurences.remove(type);
    }

    // QCStatements
    type = Extension.qCStatements;
    if (occurences.contains(type) && (qcStatments != null || qcStatementsOption != null)) {
      if (qcStatments != null) {
        values.addExtension(type, qcStatments);
        occurences.remove(type);
      } else if (requestedExtensions != null && qcStatementsOption != null) {
        // extract the euLimit data from request
        Extension extension = requestedExtensions.getExtension(type);
        if (extension == null) {
          throw new BadCertTemplateException(
              "No QCStatement extension is contained in the request");
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(extension.getParsedValue());

        Map<String, int[]> qcEuLimits = new HashMap<>();
        final int n = seq.size();
        for (int i = 0; i < n; i++) {
          QCStatement stmt = QCStatement.getInstance(seq.getObjectAt(i));
          if (!ObjectIdentifiers.id_etsi_qcs_QcLimitValue.equals(stmt.getStatementId())) {
            continue;
          }

          MonetaryValue monetaryValue = MonetaryValue.getInstance(
              stmt.getStatementInfo());
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
            throw new BadCertTemplateException(
                "no EuLimitValue is specified for currency '" + currencyS + "'");
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

          MonetaryValue monetaryVale = new MonetaryValue(monetaryOption.getCurrency(), amount,
              exponent);
          QCStatement qcStatment = new QCStatement(m.getStatementId(), monetaryVale);
          vec.add(qcStatment);
        }

        ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(),
            new DERSequence(vec));
        values.addExtension(type, extValue);
        occurences.remove(type);
      } else {
        throw new IllegalStateException("should not reach here");
      }
    }

    // BiometricData
    type = Extension.biometricInfo;
    if (occurences.contains(type) && biometricInfo != null) {
      Extension extension = (requestedExtensions == null) ? null
          : requestedExtensions.getExtension(type);
      if (extension == null) {
        throw new BadCertTemplateException(
            "no biometricInfo extension is contained in the request");
      }
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
        if (!biometricInfo.isTypePermitted(bdType)) {
          throw new BadCertTemplateException(
              "biometricInfo[" + i + "].typeOfBiometricData is not permitted");
        }

        ASN1ObjectIdentifier hashAlgo = bd.getHashAlgorithm().getAlgorithm();
        if (!biometricInfo.isHashAlgorithmPermitted(hashAlgo)) {
          throw new BadCertTemplateException(
              "biometricInfo[" + i + "].hashAlgorithm is not permitted");
        }

        int expHashValueSize;
        try {
          expHashValueSize = AlgorithmUtil.getHashOutputSizeInOctets(hashAlgo);
        } catch (NoSuchAlgorithmException ex) {
          throw new CertprofileException("should not happen, unknown hash algorithm " + hashAlgo);
        }

        byte[] hashValue = bd.getBiometricDataHash().getOctets();
        if (hashValue.length != expHashValueSize) {
          throw new BadCertTemplateException(
              "biometricInfo[" + i + "].biometricDataHash has incorrect length");
        }

        DERIA5String sourceDataUri = bd.getSourceDataUri();
        switch (biometricInfo.getSourceDataUriOccurrence()) {
          case forbidden:
            sourceDataUri = null;
            break;
          case required:
            if (sourceDataUri == null) {
              throw new BadCertTemplateException("biometricInfo[" + i
                + "].sourceDataUri is not specified in request but is required");
            }
            break;
          case optional:
            break;
          default:
            throw new BadCertTemplateException("could not reach here, unknown tripleState");
        }

        AlgorithmIdentifier newHashAlg = new AlgorithmIdentifier(hashAlgo, DERNull.INSTANCE);
        BiometricData newBiometricData = new BiometricData(bdType, newHashAlg,
            new DEROctetString(hashValue), sourceDataUri);
        vec.add(newBiometricData);
      }

      ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(),
          new DERSequence(vec));
      values.addExtension(type, extValue);
      occurences.remove(type);
    }

    // TlsFeature
    type = ObjectIdentifiers.id_pe_tlsfeature;
    if (tlsFeature != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, tlsFeature);
      }
    }

    // AuthorizationTemplate
    type = ObjectIdentifiers.id_xipki_ext_authorizationTemplate;
    if (authorizationTemplate != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, authorizationTemplate);
      }
    }

    // SMIME
    type = ObjectIdentifiers.id_smimeCapabilities;
    if (smimeCapabilities != null) {
      if (occurences.remove(type)) {
        values.addExtension(type, smimeCapabilities);
      }
    }

    // constant extensions
    if (constantExtensions != null) {
      for (ASN1ObjectIdentifier m : constantExtensions.keySet()) {
        if (!occurences.remove(m)) {
          continue;
        }

        ExtensionValue extensionValue = constantExtensions.get(m);
        if (extensionValue != null) {
          values.addExtension(m, extensionValue);
        }
      }
    }

    ExtensionValues extraExtensions = getExtraExtensions(extensionOccurences, requestedSubject,
        grantedSubject, requestedExtensions, notBefore, notAfter, caInfo);
    if (extraExtensions != null) {
      for (ASN1ObjectIdentifier m : extraExtensions.getExtensionTypes()) {
        values.addExtension(m, extraExtensions.getExtensionValue(m));
      }
    }
    return values;
  } // method getExtensions

  protected ExtensionValues getExtraExtensions(
      Map<ASN1ObjectIdentifier, ExtensionControl> extensionOccurences,
      X500Name requestedSubject, X500Name grantedSubject, Extensions requestedExtensions,
      Date notBefore, Date notAfter, PublicCaInfo caInfo)
          throws CertprofileException, BadCertTemplateException {
    return null;
  }

  private GeneralNames createRequestedSubjectAltNames(X500Name requestedSubject,
      X500Name grantedSubject, Extensions requestedExtensions)
      throws BadCertTemplateException {
    ASN1Encodable extValue = (requestedExtensions == null) ? null
        : requestedExtensions.getExtensionParsedValue(Extension.subjectAlternativeName);

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
      for (ASN1ObjectIdentifier attrType : subjectToSubjectAltNameModes.keySet()) {
        GeneralNameTag tag = subjectToSubjectAltNameModes.get(attrType);

        RDN[] rdns = grantedSubject.getRDNs(attrType);
        if (rdns == null) {
          rdns = requestedSubject.getRDNs(attrType);
        }

        if (rdns == null) {
          continue;
        }

        for (RDN rdn : rdns) {
          String rdnValue = X509Util.rdnValueToString(rdn.getFirst().getValue());
          switch (tag) {
            case rfc822Name:
            case DNSName:
            case uniformResourceIdentifier:
            case IPAddress:
            case directoryName:
            case registeredID:
              grantedNames.add(new GeneralName(tag.getTag(), rdnValue));
              break;
            default:
              throw new IllegalStateException(
                  "should not reach here, unknown GeneralName tag " + tag);
          } // end switch (tag)
        }
      }
    }

    // copy the requested SubjectAltName entries
    if (reqNames != null) {
      GeneralName[] reqL = reqNames.getNames();
      for (int i = 0; i < reqL.length; i++) {
        grantedNames.add(createGeneralName(reqL[i], subjectAltNameModes));
      }
    }

    return grantedNames.isEmpty() ? null :
      new GeneralNames(grantedNames.toArray(new GeneralName[0]));
  }

  @Override
  public Set<KeyUsageControl> getKeyUsage() {
    return keyusages;
  }

  @Override
  public Set<ExtKeyUsageControl> getExtendedKeyUsages() {
    return extendedKeyusages;
  }

  @Override
  public CertLevel getCertLevel() {
    return certLevel;
  }

  @Override
  public KeypairGenControl getKeypairGenControl() {
    return keypairGenControl;
  }

  @Override
  public Integer getPathLenBasicConstraint() {
    return pathLen;
  }

  @Override
  public AuthorityInfoAccessControl getAiaControl() {
    return aiaControl;
  }

  @Override
  public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls() {
    return extensionControls;
  }

  @Override
  public boolean isOnlyForRa() {
    return raOnly;
  }

  @Override
  public int getMaxCertSize() {
    return (maxSize == null) ? super.getMaxCertSize() : maxSize;
  }

  @Override
  public boolean includesIssuerAndSerialInAki() {
    return includeIssuerAndSerialInAki;
  }

  @Override
  public SubjectControl getSubjectControl() {
    return subjectControl;
  }

  public NotBeforeOption getNotBeforeOption() {
    return notBeforeOption;
  }

  @Override
  public Date getNotBefore(Date requestedNotBefore) {
    return notBeforeOption.getNotBefore(requestedNotBefore);
  }

  @Override
  public boolean isSerialNumberInReqPermitted() {
    return serialNumberInReqPermitted;
  }

  @Override
  public Map<ASN1ObjectIdentifier, KeyParametersOption> getKeyAlgorithms() {
    return keyAlgorithms;
  }

  @Override
  public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> getSubjectInfoAccessModes() {
    return subjectInfoAccessModes;
  }

  @Override
  public X509CertVersion getVersion() {
    return version;
  }

  @Override
  public List<String> getSignatureAlgorithms() {
    return signatureAlgorithms;
  }

  @Override
  public boolean incSerialNumberIfSubjectExists() {
    return incSerialNoIfSubjectExists;
  }

  public ExtensionValue getAdditionalInformation() {
    return additionalInformation;
  }

  public AdmissionSyntaxOption getAdmission() {
    return admission;
  }

  public Map<ASN1ObjectIdentifier, GeneralNameTag> getSubjectToSubjectAltNameModes() {
    return subjectToSubjectAltNameModes;
  }

  public Set<GeneralNameMode> getSubjectAltNameModes() {
    return subjectAltNameModes;
  }

  public ExtensionValue getAuthorizationTemplate() {
    return authorizationTemplate;
  }

  public BiometricInfoOption getBiometricInfo() {
    return biometricInfo;
  }

  public ExtensionValue getCertificatePolicies() {
    return certificatePolicies;
  }

  public Map<ASN1ObjectIdentifier, ExtensionValue> getConstantExtensions() {
    return constantExtensions;
  }

  public Set<ExtKeyUsageControl> getExtendedKeyusages() {
    return extendedKeyusages;
  }

  public boolean isIncludeIssuerAndSerialInAki() {
    return includeIssuerAndSerialInAki;
  }

  public boolean isIncSerialNoIfSubjectExists() {
    return incSerialNoIfSubjectExists;
  }

  public ExtensionValue getInhibitAnyPolicy() {
    return inhibitAnyPolicy;
  }

  public Set<KeyUsageControl> getKeyusages() {
    return keyusages;
  }

  public Integer getMaxSize() {
    return maxSize;
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

  public boolean isRaOnly() {
    return raOnly;
  }

  public ExtensionValue getRestriction() {
    return restriction;
  }

  public ExtensionValue getSmimeCapabilities() {
    return smimeCapabilities;
  }

  public ExtensionValue getTlsFeature() {
    return tlsFeature;
  }

  public ExtensionValue getValidityModel() {
    return validityModel;
  }

  public SubjectDirectoryAttributesControl getSubjectDirAttrsControl() {
    return subjectDirAttrsControl;
  }

  private static ExtensionType getExtension(ASN1ObjectIdentifier type,
      Map<String, ExtensionType> extensions) throws CertprofileException {
    ExtensionType extension = extensions.get(type.getId());
    if (extension == null) {
      throw new IllegalStateException("should not reach here: undefined extension "
          + ObjectIdentifiers.oidToDisplayName(type));
    }

    return extension;
  } // method getExtensionValue

  private static ASN1Encodable readAsn1Encodable(byte[] encoded) throws CertprofileException {
    ASN1StreamParser parser = new ASN1StreamParser(encoded);
    try {
      return parser.readObject();
    } catch (IOException ex) {
      throw new CertprofileException("could not parse the constant extension value", ex);
    }
  }

}
