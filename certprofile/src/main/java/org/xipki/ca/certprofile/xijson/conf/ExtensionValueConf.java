// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.api.profile.id.AbstractID;
import org.xipki.ca.api.profile.id.AccessMethodID;
import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.ca.api.profile.id.ExtendedKeyUsageID;
import org.xipki.ca.api.profile.id.QCStatementID;
import org.xipki.ca.certprofile.xijson.CertificatePolicyInformation;
import org.xipki.ca.certprofile.xijson.CertificatePolicyQualifier;
import org.xipki.ca.certprofile.xijson.KeyUsageControl;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeySpec;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.TripleState;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CollectionUtil;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Extension value configuration.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class ExtensionValueConf implements JsonEncodable {
  /**
   * Extension AuthorityInfoAccess.
   */
  public static class AuthorityInfoAccess implements JsonEncodable {

    private final boolean includeCaIssuers;

    private final boolean includeOcsp;

    public AuthorityInfoAccess(boolean includeCaIssuers, boolean includeOcsp) {
      this.includeCaIssuers = includeCaIssuers;
      this.includeOcsp = includeOcsp;
    }

    public boolean isIncludeCaIssuers() {
      return includeCaIssuers;
    }

    public boolean isIncludeOcsp() {
      return includeOcsp;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("includeCaIssuers", includeCaIssuers)
          .put("includeOcsp", includeOcsp);
    }

    public static AuthorityInfoAccess parse(JsonMap json) throws CodecException {
      return new AuthorityInfoAccess(json.getBool("includeCaIssuers", false),
          json.getBool("includeOcsp", false));
    }

  }

  /**
   * Extension BasicConstraints.
   */
  public static class BasicConstraints implements JsonEncodable {

    private final int pathLen;

    public BasicConstraints(int pathLen) {
      this.pathLen = Args.notNegative(pathLen, "pathLen");
    }

    public int pathLen() {
      return pathLen;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("pathLen", pathLen);
    }

    public static BasicConstraints parse(JsonMap json) throws CodecException {
      return new BasicConstraints(json.getNnInt("pathLen"));
    }

  } // class BasicConstraints

  /**
   * Extension BiometricInfo.
   */
  public static class BiometricInfo implements JsonEncodable {

    public enum BiometricType {

      picture,
      handwrittenSignature

    } // class BiometricTypeType

    private final List<BiometricType> types;

    private final List<HashAlgo> hashAlgorithms;

    private final TripleState includeSourceDataUri;

    public BiometricInfo(List<BiometricType> types, List<HashAlgo> hashAlgorithms,
                        TripleState includeSourceDataUri) {
      this.types = Args.notEmpty(types, "types");
      this.hashAlgorithms = Args.notEmpty(hashAlgorithms, "hashAlgorithms");
      this.includeSourceDataUri = Args.notNull(includeSourceDataUri, "includeSourceDataUri");
    }

    public TripleState includeSourceDataUri() {
      return includeSourceDataUri;
    }

    public boolean allowsHashAlgo(HashAlgo hashAlgo) {
      return hashAlgorithms != null && hashAlgorithms.contains(hashAlgo);
    }

    public boolean allowsType(int type) {
      for (BiometricType t : types) {
        if (t == BiometricType.picture) {
          if (type == 0) {
            return true;
          }
        } else if (t == BiometricType.handwrittenSignature) {
          if (type == 1) {
            return true;
          }
        }
      }

      return false;
    }

    @Override
    public JsonMap toCodec() {
      List<String> hashAlgorithmsList = new ArrayList<>(hashAlgorithms.size());
      for (HashAlgo hashAlgo : hashAlgorithms) {
        hashAlgorithmsList.add(hashAlgo.jceName());
      }

      return new JsonMap().putEnums("types", types, true)
          .putStrings("hashAlgorithms", hashAlgorithmsList)
          .putEnum("includeSourceDataUri", includeSourceDataUri);
    }

    public static BiometricInfo parse(JsonMap json) throws CodecException {
      List<String> list = json.getStringList("hashAlgorithms");
      List<HashAlgo> hashAlgorithms = new ArrayList<>(list.size());
      for (String v : list) {
        try {
          hashAlgorithms.add(HashAlgo.getInstance(v));
        } catch (NoSuchAlgorithmException e) {
          throw new CodecException(e);
        }
      }

      return new BiometricInfo(
          json.getEnumList("types", BiometricInfo.BiometricType.class), hashAlgorithms,
          json.getNnEnum("includeSourceDataUri", TripleState.class));
    }

  } // class BiometricInfo

  /**
   * Extension CCC Instance CA ExtensionSchema.
   */
  public static class CCCInstanceCAExtensionSchema extends CCCSimpleExtensionSchema {

    private final long appletVersion;

    private byte[] platformInformation;

    public CCCInstanceCAExtensionSchema(int version, long appletVersion) {
      super(version);
      this.appletVersion = Args.range(appletVersion, "appletVersion",
      1, 0xFFFFFFFFL);
    }

    public long appletVersion() {
      return appletVersion;
    }

    public byte[] platformInformation() {
      return platformInformation;
    }

    public void setPlatformInformation(byte[] platformInformation) {
      this.platformInformation = platformInformation;
    }

    public JsonMap toCodec() {
      return super.toCodec().put("appletVersion", appletVersion)
          .put("platformInformation", platformInformation);
    }

    public static CCCInstanceCAExtensionSchema parse(JsonMap json) throws CodecException {
      CCCInstanceCAExtensionSchema ret = new CCCInstanceCAExtensionSchema(
          json.getNnInt("version"), json.getNnInt("appletVersion"));
      ret.setPlatformInformation(json.getBytes("platformInformation"));
      return ret;
    }

  }

  /**
   * Extension CCC simple ExtensionSchema.
   */

  public static class CCCSimpleExtensionSchema implements JsonEncodable {

    private final int version;

    public CCCSimpleExtensionSchema(int version) {
      this.version = version;
    }

    public int version() {
      return version;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("version", version);
    }

    public static CCCSimpleExtensionSchema parse(JsonMap json) throws CodecException {
      return new CCCSimpleExtensionSchema(json.getNnInt("version"));
    }

  }

  /**
   * Extension TlsFeature.
   */
  public static class TlsFeature implements JsonEncodable {

    private final List<Integer> features;

    public TlsFeature(List<Integer> features) {
      Args.notEmpty(features, "features");
      for (int feature : features) {
        if (feature < 0 || feature > 65535) {
          throw new IllegalArgumentException("feature non in [0, 65535]: " + feature);
        }
      }

      this.features = features;
    }

    public List<Integer> features() {
      return features;
    }

    @Override
    public JsonMap toCodec() {
      List<Integer> list = new ArrayList<>(features);
      Collections.sort(list);

      JsonList jList = new JsonList();
      for (Integer i : list) {
        jList.add(i);
      }
      return new JsonMap().put("features", jList);
    }

    public static TlsFeature parse(JsonMap json) throws CodecException {
      return new TlsFeature(json.getNnList("features").toIntList());
    }

  } // class TlsFeature

  /**
   * Extension SubjectInfoAccess.
   */
  public static class SubjectInfoAccess implements JsonEncodable {

    private final List<Access> accesses;

    public SubjectInfoAccess(List<Access> accesses) {
      this.accesses = Args.notEmpty(accesses, "accesses");
    }

    public List<Access> accesses() {
      return accesses;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEncodables("accesses", accesses);
    }

    public static SubjectInfoAccess parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("accesses");
      List<Access> accesses = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        accesses.add(Access.parse(v));
      }
      return new SubjectInfoAccess(accesses);
    }
  }

  public static class Access implements JsonEncodable {

    private final AccessMethodID accessMethod;

    private final GeneralNameType accessLocation;

    public Access(AccessMethodID accessMethod, GeneralNameType accessLocation) {
      this.accessMethod = Args.notNull(accessMethod, "accessMethod");
      this.accessLocation = Args.notNull(accessLocation, "accessLocation");
    }

    public AccessMethodID accessMethod() {
      return accessMethod;
    }

    public GeneralNameType accessLocation() {
      return accessLocation;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("accessMethod", accessMethod.mainAlias())
          .put("accessLocation", accessLocation);
    }

    public static Access parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("accessLocation");
      GeneralNameType accessLocation = (map == null) ? null : GeneralNameType.parse(map);
      return new Access(
          AccessMethodID.ofOidOrName(json.getNnString("accessMethod")), accessLocation);
    }

  }

  /**
   * Extension S/MIME Capabilities.
   */
  public static class SmimeCapabilities implements JsonEncodable {

    private final List<SmimeCapability> capabilities;

    public SmimeCapabilities(List<SmimeCapability> capabilities) {
      this.capabilities = Args.notEmpty(capabilities, "capabilities");
    }

    public List<SmimeCapability> capabilities() {
      return capabilities;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEncodables("capabilities", capabilities);
    }

    public static SmimeCapabilities parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("capabilities");
      List<SmimeCapability> capabilities = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        capabilities.add(SmimeCapability.parse(v));
      }
      return new SmimeCapabilities(capabilities);
    }

  } // class SmimeCapabilities

  public static class SmimeCapability implements JsonEncodable {

    private final ASN1ObjectIdentifier capabilityId;

    private final Integer parameter;

    public SmimeCapability(ASN1ObjectIdentifier capabilityId, Integer parameter) {
      this.capabilityId = Args.notNull(capabilityId, "capabilityId");
      this.parameter = parameter;
    }

    public ASN1ObjectIdentifier capabilityId() {
      return capabilityId;
    }

    public Integer parameter() {
      return parameter;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("capabilityId", capabilityId.getId()).put("parameter", parameter);
    }

    public static SmimeCapability parse(JsonMap json) throws CodecException {
      return new SmimeCapability(new ASN1ObjectIdentifier(json.getNnString("capabilityId")),
          json.getInt("parameter"));
    }

  } // class SmimeCapability

  /**
   * Single Key Usages.
   */
  public static class SingleKeyUsages implements JsonEncodable {

    private List<KeySpec> appliesTo;

    private List<org.xipki.security.pkix.KeyUsage> required;

    private List<org.xipki.security.pkix.KeyUsage> optional;

    public SingleKeyUsages(List<KeySpec> appliesTo, List<org.xipki.security.pkix.KeyUsage> required,
                          List<org.xipki.security.pkix.KeyUsage> optional) {
      if (CollectionUtil.isEmpty(required) && CollectionUtil.isEmpty(optional)) {
        throw new IllegalArgumentException("required and optional can not both be empty");
      }

      this.appliesTo = appliesTo;
      this.required = required;
      this.optional = optional;
    }

    public void setRequired(List<org.xipki.security.pkix.KeyUsage> required) {
      this.required = required;
    }

    public List<org.xipki.security.pkix.KeyUsage> required() {
      return required;
    }

    public void setAppliesTo(List<KeySpec> appliesTo) {
      this.appliesTo = appliesTo;
    }

    public List<KeySpec> appliesTo() {
      return appliesTo;
    }

    public void setOptional(List<org.xipki.security.pkix.KeyUsage> optional) {
      this.optional = optional;
    }

    public List<org.xipki.security.pkix.KeyUsage> optional() {
      return optional;
    }

    public KeyUsageControl.KeySingleUsages toXiKeyUsageOptions() {
      Set<KeySingleUsage> controls = new HashSet<>();

      if (required != null) {
        for (org.xipki.security.pkix.KeyUsage usage : required) {
          controls.add(new KeySingleUsage(usage, true));
        }
      }

      if (optional != null) {
        for (org.xipki.security.pkix.KeyUsage usage : optional) {
          controls.add(new KeySingleUsage(usage, false));
        }
      }

      return new KeyUsageControl.KeySingleUsages(appliesTo, controls);
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      if (appliesTo != null) {
        List<String> list = new ArrayList<>(appliesTo.size());
        for (KeySpec v : appliesTo) {
          list.add(v.name().replace('_', '-'));
        }
        ret.putStrings("appliesTo", list, true);
      }

      ret.putEnums("required", required, true);
      ret.putEnums("optional", optional, true);
      return ret;
    }

    public static SingleKeyUsages parse(JsonMap json) throws CodecException {
      List<KeySpec> appliesTo = null;
      List<String> list = json.getStringList("appliesTo");
      if (list != null) {
        appliesTo = new ArrayList<>();
        for (String v : list) {
          try {
            appliesTo.add(KeySpec.ofKeySpec(v));
          } catch (NoSuchAlgorithmException e) {
            throw new CodecException(e);
          }
        }
      }

      list = json.getStringList("required");
      List<org.xipki.security.pkix.KeyUsage> required = (list == null) ? null : toKeyUsages(list);

      list = json.getStringList("optional");
      List<org.xipki.security.pkix.KeyUsage> optional = (list == null) ? null : toKeyUsages(list);

      return new SingleKeyUsages(appliesTo, required, optional);
    }

    private static List<org.xipki.security.pkix.KeyUsage> toKeyUsages(List<String> usageTexts) {
      List<org.xipki.security.pkix.KeyUsage> ret = new ArrayList<>(usageTexts.size());
      for (String v : usageTexts) {
        ret.add(org.xipki.security.pkix.KeyUsage.getKeyUsage(v));
      }
      return ret;
    }

  }

  /**
   * Extension QCStatements.
   */
  public static class QcStatements implements JsonEncodable {

    private final List<QcStatementType> qcStatements;

    public QcStatements(List<QcStatementType> qcStatements) {
      this.qcStatements = Args.notEmpty(qcStatements, "qcStatements");
    }

    public List<QcStatementType> qcStatements() {
      return qcStatements;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEncodables("qcStatements", qcStatements);
    }

    public static QcStatements parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("qcStatements");
      List<QcStatementType> qcStatements = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        qcStatements.add(QcStatementType.parse(v));
      }
      return new QcStatements(qcStatements);
    }

  } // class QcStatements

  public static class Range2Type implements JsonEncodable {

    private final int min;

    private final int max;

    public Range2Type(int min, int max) {
      this.min = min;
      this.max = Args.min(max, "max", min);
    }

    public int min() {
      return min;
    }

    public int max() {
      return max;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("min", min).put("max", max);
    }

    public static Range2Type parse(JsonMap json) throws CodecException {
      return new Range2Type(json.getNnInt("min"), json.getNnInt("max"));
    }

  } // method Range2Type

  public static class QcStatementValueType implements JsonEncodable {

    private final ConstantExtnValue constant;

    private final Integer qcRetentionPeriod;

    private final QcEuLimitValueType qcEuLimitValue;

    private final List<PdsLocationType> pdsLocations;

    public QcStatementValueType(
        ConstantExtnValue constant, Integer qcRetentionPeriod,
        QcEuLimitValueType qcEuLimitValue, List<PdsLocationType> pdsLocations) {
      int num = 0;
      if (constant != null) num++;

      if (qcRetentionPeriod != null) num++;

      if (qcEuLimitValue != null) num++;

      if (CollectionUtil.isNotEmpty(pdsLocations)) num++;

      if (num != 1) {
        throw new IllegalArgumentException("Not exactly one of constant, " +
            "qcRetentionPeriod, qcEuLimitValue, pdsLocations is set");
      }

      this.constant = constant;
      this.qcRetentionPeriod = qcRetentionPeriod;
      this.qcEuLimitValue = qcEuLimitValue;
      this.pdsLocations = pdsLocations;
    }

    public ConstantExtnValue constant() {
      return constant;
    }

    public Integer qcRetentionPeriod() {
      return qcRetentionPeriod;
    }

    public QcEuLimitValueType qcEuLimitValue() {
      return qcEuLimitValue;
    }

    public List<PdsLocationType> pdsLocations() {
      return pdsLocations;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("constant", constant).put("qcRetentionPeriod", qcRetentionPeriod)
          .put("qcEuLimitValue", qcEuLimitValue).putEncodables("pdsLocations", pdsLocations);
    }

    public static QcStatementValueType parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("constant");
      ConstantExtnValue constant = (map == null) ? null : ConstantExtnValue.parse(map);

      map = json.getMap("qcEuLimitValue");
      QcEuLimitValueType qcEuLimitValue = (map == null) ? null : QcEuLimitValueType.parse(map);

      JsonList list = json.getList("pdsLocations");
      List<PdsLocationType> pdsLocations = null;
      if (list != null) {
        pdsLocations = new ArrayList<>(list.size());
        for (JsonMap v : list.toMapList()) {
          pdsLocations.add(PdsLocationType.parse(v));
        }
      }
      return new QcStatementValueType(constant, json.getInt("qcRetentionPeriod"),
          qcEuLimitValue, pdsLocations);
    }

  } // class QcStatementValueType

  public static class QcStatementType implements JsonEncodable {

    private final QCStatementID statementId;

    private final QcStatementValueType statementValue;

    public QcStatementType(QCStatementID statementId, QcStatementValueType statementValue) {
      this.statementId = Args.notNull(statementId, "statementId");
      this.statementValue = statementValue;
    }

    public QCStatementID statementId() {
      return statementId;
    }

    public QcStatementValueType statementValue() {
      return statementValue;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("statementId", statementId.mainAlias())
          .put("statementValue", statementValue);
    }

    public static QcStatementType parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("statementValue");
      QcStatementValueType statementValue = (map == null) ? null : QcStatementValueType.parse(map);
      return new QcStatementType(
          QCStatementID.ofOidOrName(json.getNnString("statementId")), statementValue);
    }

  }

  public static class PdsLocationType implements JsonEncodable {

    private final String url;

    private final String language;

    public PdsLocationType(String url, String language) {
      this.url = Args.notBlank(url, "url");
      this.language = Args.notBlank(language, "language");
    }

    public String url() {
      return url;
    }

    public String language() {
      return language;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("url", url).put("language", language);
    }

    public static PdsLocationType parse(JsonMap json) throws CodecException {
      return new PdsLocationType(json.getNnString("url"), json.getNnString("language"));
    }

  } // class QcEuLimitValueType

  public static class QcEuLimitValueType implements JsonEncodable {

    private final String currency;

    private final Range2Type amount;

    private final Range2Type exponent;

    public QcEuLimitValueType(String currency, Range2Type amount, Range2Type exponent) {
      this.currency = Args.notBlank(currency, "currency");
      this.amount   = Args.notNull(amount, "amount");
      this.exponent = Args.notNull(exponent, "exponent");
    }

    public String currency() {
      return currency;
    }

    public Range2Type amount() {
      return amount;
    }

    public Range2Type exponent() {
      return exponent;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("currency", currency)
          .put("amount", amount).put("exponent", exponent);
    }

    public static QcEuLimitValueType parse(JsonMap json) throws CodecException {
      return new QcEuLimitValueType(json.getNnString("currency"),
          Range2Type.parse(json.getNnMap("amount")),
          Range2Type.parse(json.getNnMap("exponent")));
    }

  } // class QcEuLimitValueType

  /**
   * Extension PrivateKeyUsagePeriod.
   */
  public static class PrivateKeyUsagePeriod implements JsonEncodable {

    private final String validity;

    public PrivateKeyUsagePeriod(String validity) {
      this.validity = Args.notBlank(validity, "validity");
    }

    public String validity() {
      return validity;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("validity", validity);
    }

    public static PrivateKeyUsagePeriod parse(JsonMap json) throws CodecException {
      return new PrivateKeyUsagePeriod(json.getNnString("validity"));
    }

  }

  /**
   * Extension PolicyMappings.
   * Only for CA.
   */
  public static class PolicyMappings implements JsonEncodable {

    private final List<PolicyIdMappingType> mappings;

    public PolicyMappings(List<PolicyIdMappingType> mappings) {
      this.mappings = Args.notEmpty(mappings, "mappings");
    }

    public List<PolicyIdMappingType> mappings() {
      return mappings;
    }

    public org.bouncycastle.asn1.x509.PolicyMappings toPolicyMappings() {
      final int n = mappings.size();

      CertPolicyId[] issuerDomainPolicy = new CertPolicyId[n];
      CertPolicyId[] subjectDomainPolicy = new CertPolicyId[n];

      for (int i = 0; i < n; i++) {
        PolicyIdMappingType mapping = mappings.get(i);
        issuerDomainPolicy[i]  = CertPolicyId.getInstance(mapping.issuerDomainPolicy().oid());
        subjectDomainPolicy[i] = CertPolicyId.getInstance(mapping.subjectDomainPolicy().oid());
      }

      return new org.bouncycastle.asn1.x509.PolicyMappings(issuerDomainPolicy, subjectDomainPolicy);
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEncodables("mappings", mappings);
    }

    public static PolicyMappings parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("mappings");
      List<PolicyIdMappingType> mappings = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        mappings.add(PolicyIdMappingType.parse(v));
      }
      return new PolicyMappings(mappings);
    }

  }

  public static class PolicyIdMappingType implements JsonEncodable {

    private final CertificatePolicyID issuerDomainPolicy;

    private final CertificatePolicyID subjectDomainPolicy;

    public PolicyIdMappingType(CertificatePolicyID issuerDomainPolicy,
                              CertificatePolicyID subjectDomainPolicy) {
      this.issuerDomainPolicy = Args.notNull(issuerDomainPolicy, "issuerDomainPolicy");
      this.subjectDomainPolicy = Args.notNull(subjectDomainPolicy, "subjectDomainPolicy");
    }

    public CertificatePolicyID issuerDomainPolicy() {
      return issuerDomainPolicy;
    }

    public CertificatePolicyID subjectDomainPolicy() {
      return subjectDomainPolicy;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      if (issuerDomainPolicy != null) {
        ret.put("issuerDomainPolicy", issuerDomainPolicy.mainAlias());
      }
      if (issuerDomainPolicy != null) {
        ret.put("subjectDomainPolicy", subjectDomainPolicy.mainAlias());
      }
      return ret;
    }

    public static PolicyIdMappingType parse(JsonMap json) throws CodecException {
      String str = json.getString("issuerDomainPolicy");
      CertificatePolicyID issuerDomainPolicy = (str == null) ? null
          : CertificatePolicyID.ofOidOrName(str);

      str = json.getString("subjectDomainPolicy");
      CertificatePolicyID subjectDomainPolicy = (str == null) ? null
          : CertificatePolicyID.ofOidOrName(str);

      return new PolicyIdMappingType(issuerDomainPolicy, subjectDomainPolicy);
    }

  } // class PolicyIdMappingType

  /**
   * Extension PolicyConstraints.
   */
  public static class PolicyConstraints implements JsonEncodable {

    private final Integer requireExplicitPolicy;

    private final Integer inhibitPolicyMapping;

    public PolicyConstraints(Integer requireExplicitPolicy, Integer inhibitPolicyMapping) {
      // Only for CA, at least one of requireExplicitPolicy and inhibitPolicyMapping must be present
      if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
        throw new IllegalArgumentException(
            "requireExplicitPolicy and inhibitPolicyMapping may not be both null");
      }

      this.requireExplicitPolicy = requireExplicitPolicy;
      this.inhibitPolicyMapping = inhibitPolicyMapping;
    }

    public Integer requireExplicitPolicy() {
      return requireExplicitPolicy;
    }

    public Integer inhibitPolicyMapping() {
      return inhibitPolicyMapping;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("requireExplicitPolicy", requireExplicitPolicy)
          .put("inhibitPolicyMapping",  inhibitPolicyMapping);
    }

    public static PolicyConstraints parse(JsonMap json) throws CodecException {
      return new PolicyConstraints(json.getInt("requireExplicitPolicy"),
          json.getInt("inhibitPolicyMapping"));
    }

  }

  /**
   * Extension NameConstraints.
   * Only for CA, at least one of permittedSubtrees and excludedSubtrees must
   * be present.
   */
  public static class NameConstraints implements JsonEncodable {

    private final List<GeneralSubtreeType> permittedSubtrees;

    private final List<GeneralSubtreeType> excludedSubtrees;

    public NameConstraints(List<GeneralSubtreeType> permittedSubtrees,
                          List<GeneralSubtreeType> excludedSubtrees) {
      if (CollectionUtil.isEmpty(permittedSubtrees)
          && CollectionUtil.isEmpty(excludedSubtrees)) {
        throw new IllegalArgumentException(
            "permittedSubtrees and excludedSubtrees may not be both null");
      }

      this.permittedSubtrees = permittedSubtrees;
      this.excludedSubtrees  = excludedSubtrees;
    }

    public List<GeneralSubtreeType> permittedSubtrees() {
      return permittedSubtrees;
    }

    public List<GeneralSubtreeType> excludedSubtrees() {
      return excludedSubtrees;
    }

    public org.bouncycastle.asn1.x509.NameConstraints toNameConstraints() {
      GeneralSubtree[] permitted = buildX509GeneralSubtrees(permittedSubtrees);
      GeneralSubtree[] excluded  = buildX509GeneralSubtrees(excludedSubtrees);
      return (permitted == null && excluded == null) ? null
          : new org.bouncycastle.asn1.x509.NameConstraints(permitted, excluded);
    }

    private static GeneralSubtree[] buildX509GeneralSubtrees(List<GeneralSubtreeType> subtrees) {
      if (CollectionUtil.isEmpty(subtrees)) {
        return null;
      }

      final int n = subtrees.size();
      GeneralSubtree[] ret = new GeneralSubtree[n];
      for (int i = 0; i < n; i++) {
        ret[i] = buildX509GeneralSubtree(subtrees.get(i));
      }

      return ret;
    }

    private static GeneralSubtree buildX509GeneralSubtree(GeneralSubtreeType type) {
      GeneralSubtreeType baseType = Args.notNull(type, "type");
      GeneralName base;
      if (baseType.directoryName() != null) {
        base = new GeneralName(X509Util.reverse(new X500Name(baseType.directoryName())));
      } else if (baseType.dnsName() != null) {
        base = new GeneralName(GeneralName.dNSName, baseType.dnsName());
      } else if (baseType.ipAddress() != null) {
        base = new GeneralName(GeneralName.iPAddress, baseType.ipAddress());
      } else if (baseType.rfc822Name() != null) {
        base = new GeneralName(GeneralName.rfc822Name, baseType.rfc822Name());
      } else if (baseType.uri() != null) {
        base = new GeneralName(GeneralName.uniformResourceIdentifier, baseType.uri());
      } else {
        throw new IllegalStateException(
            "should not reach here, unknown child of GeneralSubtreeType");
      }

      return new GeneralSubtree(base, null, null);
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEncodables("permittedSubtrees", permittedSubtrees)
          .putEncodables("excludedSubtrees", excludedSubtrees);
    }

    public static NameConstraints parse(JsonMap json) throws CodecException {
      List<GeneralSubtreeType> permittedSubtrees = null;
      JsonList list = json.getList("permittedSubtrees");
      if (list != null) {
        permittedSubtrees = GeneralSubtreeType.parse(list);
      }

      List<GeneralSubtreeType> excludedSubtrees = null;
      list = json.getList("excludedSubtrees");
      if (list != null) {
        excludedSubtrees = GeneralSubtreeType.parse(list);
      }

      return new NameConstraints(permittedSubtrees, excludedSubtrees);
    }

  } // class NameConstraints

  /**
   * Extension KeyUsage.
   */
  public static class KeyUsage implements JsonEncodable {

    private final List<SingleKeyUsages> usages;

    public KeyUsage(List<SingleKeyUsages> usages) {
      this.usages = Args.notEmpty(usages, "usages");
    }

    public List<SingleKeyUsages> usages() {
      return usages;
    }

    public KeyUsageControl toXiKeyUsageOptions() {
      List<KeyUsageControl.KeySingleUsages> singleUsagesList = new ArrayList<>(usages.size());
      for (SingleKeyUsages x : usages) {
        singleUsagesList.add(x.toXiKeyUsageOptions());
      }
      return new KeyUsageControl(singleUsagesList);
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEncodables("usages", usages);
    }

    public static KeyUsage parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("usages");
      List<SingleKeyUsages> usagesList = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        usagesList.add(SingleKeyUsages.parse(v));
      }
      return new KeyUsage(usagesList);
    }

  }

  /**
   * Extension CertificatePolicies.
   */
  public static class CertificatePolicies implements JsonEncodable {

    private final List<CertificatePolicyInformationType> certificatePolicyInformations;

    public CertificatePolicies(
        List<CertificatePolicyInformationType> certificatePolicyInformations) {
      this.certificatePolicyInformations = Args.notEmpty(
          certificatePolicyInformations, "certificatePolicyInformations");
    }

    public List<CertificatePolicyInformationType> certificatePolicyInformations() {
      return certificatePolicyInformations;
    }

    public org.bouncycastle.asn1.x509.CertificatePolicies toCertificatePolicies() {
      List<CertificatePolicyInformation> policyInfos = toPolicyInfos();

      int size = policyInfos.size();
      PolicyInformation[] infos = new PolicyInformation[size];

      int idx = 0;
      for (CertificatePolicyInformation policyInfo : policyInfos) {
        List<CertificatePolicyQualifier> qualifiers = policyInfo.qualifiers();
        ASN1Sequence policyQualifiers = CollectionUtil.isEmpty(qualifiers)
            ? null : createX509PolicyQualifiers(qualifiers);
        CertificatePolicyID policyOid = policyInfo.certPolicyId();

        infos[idx++] = (policyQualifiers == null)
            ? new PolicyInformation(policyOid.oid())
            : new PolicyInformation(policyOid.oid(), policyQualifiers);
      }

      return new org.bouncycastle.asn1.x509.CertificatePolicies(infos);
    } // method toX509CertificatePolicies

    private  static ASN1Sequence createX509PolicyQualifiers(
        List<CertificatePolicyQualifier> qualifiers) {
      ASN1EncodableVector qualifierInfos = new ASN1EncodableVector();
      for (CertificatePolicyQualifier qualifier : qualifiers) {
        PolicyQualifierInfo qualifierInfo;
        if (qualifier.cpsUri() != null) {
          qualifierInfo = new PolicyQualifierInfo(qualifier.cpsUri());
        } else if (qualifier.userNotice() != null) {
          UserNotice userNotice = new UserNotice(null, qualifier.userNotice());
          qualifierInfo = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, userNotice);
        } else {
          qualifierInfo = null;
        }

        if (qualifierInfo != null) {
          qualifierInfos.add(qualifierInfo);
        }
        //PolicyQualifierId qualifierId
      }

      return new DERSequence(qualifierInfos);
    } // method createPolicyQualifiers

    private List<CertificatePolicyInformation> toPolicyInfos() {
      List<CertificatePolicyInformationType> policyPairs = certificatePolicyInformations();
      List<CertificatePolicyInformation> ret = new ArrayList<>(policyPairs.size());

      for (CertificatePolicyInformationType policyPair : policyPairs) {
        List<CertificatePolicyQualifier> qualifiers = null;
        if (CollectionUtil.isNotEmpty(policyPair.policyQualifiers)) {
          qualifiers = new ArrayList<>(policyPair.policyQualifiers.size());
          for (PolicyQualifier m : policyPair.policyQualifiers) {
            if (m.type() == PolicyQualifierType.cpsUri) {
              qualifiers.add(CertificatePolicyQualifier.getInstanceForCpsUri(m.value));
            } else {
              qualifiers.add(CertificatePolicyQualifier.getInstanceForUserNotice(m.value));
            }
          }
        }

        ret.add(new CertificatePolicyInformation(policyPair.policyIdentifier(), qualifiers));
      }

      return ret;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEncodables("certificatePolicyInformations",
          this.certificatePolicyInformations);
    }

    public static CertificatePolicies parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("certificatePolicyInformations");
      List<CertificatePolicyInformationType> types = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        types.add(CertificatePolicyInformationType.parse(v));
      }

      return new CertificatePolicies(types);
    }

  }

  public enum PolicyQualifierType {
    cpsUri,
    userNotice
  }

  public static class PolicyQualifier implements JsonEncodable {

    private final PolicyQualifierType type;

    private final String value;

    public PolicyQualifier(PolicyQualifierType type, String value) {
      this.type  = Args.notNull(type, "type");
      this.value = Args.notBlank(value, "value");
    }

    public PolicyQualifierType type() {
      return type;
    }

    public String value() {
      return value;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEnum("type", type).put("value", value);
    }

    public static PolicyQualifier parse(JsonMap json) throws CodecException {
      return new PolicyQualifier(PolicyQualifierType.valueOf(json.getNnString("type")),
          json.getNnString("value"));
    }

  } // class PolicyQualifier

  public static class CertificatePolicyInformationType implements JsonEncodable {

    private final CertificatePolicyID policyIdentifier;

    private final List<PolicyQualifier> policyQualifiers;

    public CertificatePolicyInformationType(
        CertificatePolicyID policyIdentifier, List<PolicyQualifier> policyQualifiers) {
      this.policyIdentifier = Args.notNull(policyIdentifier, "policyIdentifier");

      if (policyQualifiers != null) {
        for (PolicyQualifier qualifier : policyQualifiers) {
          if (qualifier.type == PolicyQualifierType.cpsUri) {
            try {
              new URI(qualifier.value);
            } catch (URISyntaxException e) {
              throw new IllegalArgumentException("invalid URI " + qualifier.value);
            }
          }
        }
      }
      this.policyQualifiers = policyQualifiers;
    }

    public CertificatePolicyID policyIdentifier() {
      return policyIdentifier;
    }

    public List<PolicyQualifier> policyQualifiers() {
      return policyQualifiers == null || policyQualifiers.isEmpty() ? null : policyQualifiers;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap().put("policyIdentifier", policyIdentifier.mainAlias());
      if (CollectionUtil.isNotEmpty(policyQualifiers)) {
        ret.putEncodables("policyQualifiers", policyQualifiers);
      }
      return ret;
    }

    public static CertificatePolicyInformationType parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("policyQualifiers");
      List<PolicyQualifier> policyQualifiers = null;
      if (list != null) {
        policyQualifiers = new ArrayList<>(list.size());
        for (JsonMap v : list.toMapList()) {
          policyQualifiers.add(PolicyQualifier.parse(v));
        }
      }

      return new CertificatePolicyInformationType(
          CertificatePolicyID.ofOidOrName(json.getNnString("policyIdentifier")),
          policyQualifiers);
    }

  }

  /**
   * Extension InhibitAnyPolicy.
   */
  public static class InhibitAnyPolicy implements JsonEncodable {

    private final int skipCerts;

    public int skipCerts() {
      return skipCerts;
    }

    public InhibitAnyPolicy(int skipCerts) {
      this.skipCerts = skipCerts;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("skipCerts", skipCerts);
    }

    public static InhibitAnyPolicy parse(JsonMap json) throws CodecException {
      return new InhibitAnyPolicy(json.getNnInt("skipCerts"));
    }
  }

  /**
   * Extension ExtendedKeyUsage.
   */
  public static class ExtendedKeyUsage implements JsonEncodable {

    private final List<ExtendedKeyUsageID> required;

    private final List<ExtendedKeyUsageID> optional;

    public ExtendedKeyUsage(List<ExtendedKeyUsageID> required, List<ExtendedKeyUsageID> optional) {
      if (CollectionUtil.isEmpty(required) && CollectionUtil.isEmpty(optional)) {
        throw new IllegalArgumentException("required and optional can not both be empty");
      }

      this.required = required;
      this.optional = optional;
    }

    public List<ExtendedKeyUsageID> required() {
      return required;
    }

    public List<ExtendedKeyUsageID> optional() {
      return optional;
    }

    public Set<ExtKeyUsageControl> toXiExtKeyUsageOptions() {
      Set<ExtKeyUsageControl> controls = new HashSet<>();

      if (required != null) {
        for (ExtendedKeyUsageID usage : required) {
          controls.add(new ExtKeyUsageControl(usage.oid(), true));
        }
      }

      if (optional != null) {
        for (ExtendedKeyUsageID usage : optional) {
          controls.add(new ExtKeyUsageControl(usage.oid(), false));
        }
      }

      return Collections.unmodifiableSet(controls);
    } // method buildExtKeyUsageOptions

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      if (required != null) {
        ret.putStrings("required", AbstractID.toJsonStringList(required));
      }

      if (optional != null) {
        ret.putStrings("optional", AbstractID.toJsonStringList(optional));
      }
      return ret;
    }

    public static ExtendedKeyUsage parse(JsonMap json) throws CodecException {
      return new ExtendedKeyUsage(toUsageIDList(json.getStringList("required")),
          toUsageIDList(json.getStringList("optional")));
    }

    private static List<ExtendedKeyUsageID> toUsageIDList(List<String> list) {
      if (list == null) {
        return null;
      }

      List<ExtendedKeyUsageID> usages = new ArrayList<>(list.size());
      for (String v : list) {
        usages.add(ExtendedKeyUsageID.ofOidOrName(v));
      }
      return usages;
    }

  } // class ExtendedKeyUsage
}
