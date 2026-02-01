// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ctrl.CertDomain;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.ExtensionControl;
import org.xipki.ca.api.profile.ctrl.ExtensionsControl;
import org.xipki.ca.api.profile.ctrl.KeypairGenControl;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.codec.TripleState;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Root configuration of the json Certprofile.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class XijsonCertprofileType implements JsonEncodable {

  private Map<String, String> metadata;

  private CertLevel certLevel;

  private CertDomain certDomain = CertDomain.RFC5280;

  private Integer maxSize;

  /**
   * The validity of the certificate to be generated, namely
   * notAfter - notBefore. Examples are:
   * <ul>
   *   <li>5y: 5 years</li>
   *   <li>365d: 365 days</li>
   *   <li>120h: 120 hours</li>
   *   <li>100m: 100 minutes</li>
   *   <li>99991231235959Z or UNDEFINED: certificate has this UNDEFINED
   *   notAfter</li>
   * </ul>
   */
  private String validity;

  /**
   * How CA assigns the notAfter field in the certificate if the requested
   * notAfter is after CA's validity.
   */
  private ValidityMode notAfterMode;

  /**
   * Value of the notBefore field.
   * <ul>
   *   <li>'current': current time</li>
   *   <li>'midnight'[:timezone]: the next mid night time for the given
   *        timezone. Valid timezones are: GMT+0, GMT+1, ..., GMT+12, GMT-1,
   *        ..., GMT-12</li>
   *   <li>'+'offset: offset after current time</li>
   *   <li>'-'offset: before after current time, In the current implementation,
   *        offset of maximal 10 minutes is allowed.
   *        The offset must have following suffixes:
   *        <ul>
   *          <li>'d' for day, e.g. '2d' for 2 days,</li>
   *          <li>'h' for day, e.g. '2h' for 2 hours,</li>
   *          <li>'m' for day, e.g. '2m' for 2 minutes,</li>
   *          <li>'s' for day, e.g. '2s' for 2 seconds.</li>
   *        </ul>
   *   </li>
   * </ul>
   */
  private String notBeforeTime;

  /**
   * Control how CA will generate the keypair for the certificate.
   * Defaults to forbidden.
   */
  private KeypairGenControl keypairGeneration;

  private List<SignAlgo> signatureAlgorithms;

  private List<KeySpec> keyAlgorithms;

  /**
   * whether the RDNs in subject RDNs occur as in the defined ASN.1 order.
   */
  private Boolean keepSubjectOrder;

  private List<RdnType> subject;

  /**
   * whether the RDNs in extensions occur as in the defined ASN.1 order.
   */
  private Boolean keepExtensionsOrder;

  private List<ExtensionType> extensions;

  public static XijsonCertprofileType parse(byte[] confBytes)
      throws CertprofileException {
    Args.notNull(confBytes, "confBytes");
    try {
      return parse(JsonParser.parseMap(confBytes, true));
    } catch (CodecException | RuntimeException ex) {
      throw new CertprofileException(
          "parse profile failed, message: " + ex.getMessage(), ex);
    }
  }

  public static XijsonCertprofileType parse(File confFile)
      throws CertprofileException {
    Args.notNull(confFile, "confFile");
    try {
      return parse(JsonParser.parseMap(confFile.toPath(), true));
    } catch (CodecException | RuntimeException ex) {
      throw new CertprofileException(
          "parse profile failed, message: " + ex.getMessage(), ex);
    }
  }

  public CertLevel certLevel() {
    return certLevel;
  }

  public void setCertLevel(CertLevel certLevel) {
    this.certLevel = certLevel;
  }

  public CertDomain certDomain() {
    return certDomain;
  }

  public void setCertDomain(CertDomain certDomain) {
    this.certDomain = certDomain;
  }

  public Map<String, String> metadata() {
    if (metadata == null) {
      metadata = new HashMap<>();
    }
    return metadata;
  }

  public void setMetadata(Map<String, String> metadata) {
    this.metadata = metadata;
  }

  public String validity() {
    return validity;
  }

  public void setValidity(String validity) {
    this.validity = validity;
  }

  public ValidityMode notAfterMode() {
    return notAfterMode;
  }

  public void setNotAfterMode(ValidityMode notAfterMode) {
    this.notAfterMode = notAfterMode;
  }

  public String notBeforeTime() {
    return notBeforeTime;
  }

  public void setNotBeforeTime(String notBeforeTime) {
    this.notBeforeTime = notBeforeTime;
  }

  public KeypairGenControl keypairGeneration() {
    return keypairGeneration;
  }

  public void setKeypairGeneration(KeypairGenControl keypairGeneration) {
    this.keypairGeneration = keypairGeneration;
  }

  public List<SignAlgo> signatureAlgorithms() {
    return signatureAlgorithms;
  }

  public void setSignatureAlgorithms(List<SignAlgo> signatureAlgorithms) {
    this.signatureAlgorithms = signatureAlgorithms;
  }

  public List<KeySpec> keyAlgorithms() {
    return keyAlgorithms;
  }

  public void setKeyAlgorithms(List<KeySpec> keyAlgorithms) {
    this.keyAlgorithms = keyAlgorithms;
  }

  public Boolean keepSubjectOrder() {
    return keepSubjectOrder;
  }

  public void setKeepSubjectOrder(Boolean keepSubjectOrder) {
    this.keepSubjectOrder = keepSubjectOrder;
  }

  public Boolean keepExtensionsOrder() {
    return keepExtensionsOrder;
  }

  public void setKeepExtensionsOrder(Boolean keepExtensionsOrder) {
    this.keepExtensionsOrder = keepExtensionsOrder;
  }

  public List<RdnType> subject() {
    if (subject == null) {
      subject = new LinkedList<>();
    }
    return subject;
  }

  public void setSubject(List<RdnType> subject) {
    this.subject = subject;
  }

  public List<ExtensionType> extensions() {
    if (extensions == null) {
      extensions = new LinkedList<>();
    }
    return extensions;
  }

  public void setExtensions(List<ExtensionType> extensions) {
    this.extensions = extensions;
  }

  public Integer maxSize() {
    return maxSize;
  }

  public void setMaxSize(Integer maxSize) {
    this.maxSize = maxSize;
  }

  public Map<String, ExtensionType> buildExtensions() {
    Map<String, ExtensionType> ret = new HashMap<>();
    for (ExtensionType m : extensions()) {
      String type = m.type().textOid();
      ret.put(type, m);
    }
    return ret;
  }

  private void validate() throws CertprofileException {
    Args.notNull(certLevel, "certLevel");
    Args.notBlank(validity, "validity");
    Args.notBlank(notBeforeTime, "notBeforeTime");
    Args.notNull(subject, "subject");
    Args.notNull(extensions, "extensions");

    Set<String> types = new HashSet<>();
    for (RdnType m : subject) {
      String type = m.type().textOid();
      if (!types.add(type)) {
        throw new CertprofileException("duplicated definition of subject "
            + OIDs.getName(m.type().oid()));
      }
    }

    types.clear();
    for (ExtensionType m : extensions) {
      String type = m.type().textOid();
      if (!types.add(type)) {
        throw new CertprofileException("duplicated definition of extension "
            + OIDs.getName(m.type().oid()));
      }
    }
  } // method validate

  public Map<ASN1ObjectIdentifier, ExtensionValue> buildConstantExtensions()
      throws CertprofileException {
    Map<ASN1ObjectIdentifier, ExtensionValue> map = new HashMap<>();

    for (ExtensionType m : extensions()) {
      ASN1ObjectIdentifier oid = m.type().oid();
      if (OIDs.Extn.subjectAlternativeName.equals(oid)
          || OIDs.Extn.subjectInfoAccess.equals(oid)
          || OIDs.Extn.biometricInfo.equals(oid)) {
        continue;
      }

      if (m.constant() == null) {
        continue;
      }

      ASN1Encodable value;
      try {
        value = m.constant().toASN1();
      } catch (IOException ex) {
        throw new CertprofileException(ex.getMessage(), ex);
      }
      ExtensionValue extension = new ExtensionValue(m.isCritical(), value);

      map.put(oid, extension);
    }

    if (CollectionUtil.isEmpty(map)) {
      return null;
    }

    return Collections.unmodifiableMap(map);
  } // buildConstantExtensions

  public ExtensionsControl buildExtensionControls()
      throws CertprofileException {
    // Extension controls
    List<ExtensionControl> controls = new LinkedList<>();
    Set<ASN1ObjectIdentifier> set = new HashSet<>();

    for (ExtensionType extn : extensions()) {
      ASN1ObjectIdentifier oid = extn.type().oid();

      if (set.contains(oid)) {
        throw new CertprofileException(
            "duplicated definition of extension " + oid.getId());
      }

      set.add(oid);

      TripleState inReq = extn.inRequest();
      if (inReq == null) {
        inReq = TripleState.forbidden;
      }

      if (inReq != TripleState.forbidden && extn.constant() != null) {
        throw new CertprofileException(
            "constant Extension is not permitted in request");
      }

      controls.add(new ExtensionControl(oid, extn.isCritical(),
          extn.isRequired(), inReq));
    }

    boolean keep = keepExtensionsOrder != null && keepExtensionsOrder;
    return new ExtensionsControl(controls, keep);
  } // method buildExtensionControls

  @Override
  public JsonMap toCodec() {
    JsonMap metadataMap = new JsonMap();
    List<String> metaKeys = new ArrayList<>(metadata.keySet());
    Collections.sort(metaKeys);
    for (String metaKey : metaKeys) {
      metadataMap.put(metaKey, metadata.get(metaKey));
    }

    JsonMap ret = new JsonMap().put("metadata",  metadataMap)
        .putEnum("certLevel", certLevel)
        .putEnum("certDomain",
            (certDomain == CertDomain.RFC5280) ? null : certDomain)
        .put("maxSize", maxSize)
        .put("validity", validity)
        .putEnum("notAfterMode", notAfterMode)
        .put("notBeforeTime", notBeforeTime);

    if (keypairGeneration != null) {
      ret.put("keypairGeneration", keypairGeneration.text());
    }

    if (signatureAlgorithms != null) {
      List<String> texts = new ArrayList<>(signatureAlgorithms.size());
      for (SignAlgo v : signatureAlgorithms) {
        texts.add(v.jceName());
      }
      ret.putStrings("signatureAlgorithms", texts);
    }

    if (keyAlgorithms != null) {
      List<String> texts = new ArrayList<>(keyAlgorithms.size());
      for (KeySpec v : keyAlgorithms) {
        texts.add(v.text());
      }
      ret.putStrings("keyAlgorithms", texts);
    }

    return ret.put("keepSubjectOrder", keepSubjectOrder)
        .putEncodables("subject", subject)
        .put("keepExtensionsOrder", keepExtensionsOrder)
        .putEncodables("extensions", extensions);
  }

  public static XijsonCertprofileType parse(JsonMap json)
      throws CodecException, CertprofileException {
    XijsonCertprofileType ret = new XijsonCertprofileType();
    ret.setMetadata(json.getStringMap("metadata"));
    ret.setCertLevel(json.getEnum("certLevel", CertLevel.class));
    CertDomain certDomain = json.getEnum("certDomain", CertDomain.class);
    if (certDomain != null) {
      ret.setCertDomain(certDomain);
    }

    ret.setMaxSize(json.getInt("maxSize"));
    ret.setValidity(json.getString("validity"));

    String str = json.getString("notAfterMode");
    if (str != null) {
      ret.setNotAfterMode(ValidityMode.forName(str));
    }

    ret.setNotBeforeTime(json.getNnString("notBeforeTime"));
    str = json.getString("keypairGeneration");
    if (str != null) {
      try {
        ret.setKeypairGeneration(KeypairGenControl.valueOf(str));
      } catch (NoSuchAlgorithmException e) {
        throw new CertprofileException(e);
      }
    }

    try {
      List<String> texts = json.getStringList("signatureAlgorithms");
      if (texts != null) {
        ret.setSignatureAlgorithms(ofSignAlgos(texts));
      }

      texts = json.getStringList("keyAlgorithms");
      if (texts != null) {
        ret.setKeyAlgorithms(KeySpec.ofKeySpecs(texts));
      }
    } catch (NoSuchAlgorithmException e) {
      throw new CertprofileException(e);
    }

    ret.setKeepSubjectOrder(json.getBool("keepSubjectOrder"));

    JsonList list = json.getNnList("subject");
    List<RdnType> subject = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      subject.add(RdnType.parse(v));
    }
    ret.setSubject(subject);

    ret.setKeepExtensionsOrder(json.getBool("keepExtensionsOrder"));

    list = json.getNnList("extensions");
    List<ExtensionType> extensions = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      extensions.add(ExtensionType.parse(v));
    }
    ret.setExtensions(extensions);

    ret.validate();
    return ret;
  }

  public static List<SignAlgo> ofSignAlgos(List<String> names)
      throws NoSuchAlgorithmException {
    List<SignAlgo> list = new ArrayList<>(names.size());
    for (String name : names) {
      list.add(ofSignAlgo(name));
    }
    return list;
  }

  private static SignAlgo ofSignAlgo(String name)
      throws NoSuchAlgorithmException {
    name = name.trim();
    String name2 = name.replace('-', '_');

    for (SignAlgo m : SignAlgo.values()) {
      String tname = m.name();
      if (tname.equalsIgnoreCase(name) || tname.equalsIgnoreCase(name2) ||
          m.jceName().equalsIgnoreCase(name)) {
        return m;
      }
    }

    throw new NoSuchAlgorithmException("unknown SignAlgo " + name);
  }

}
