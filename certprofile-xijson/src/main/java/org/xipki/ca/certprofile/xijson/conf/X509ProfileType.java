// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.Certprofile.CertDomain;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.ca.api.profile.Certprofile.X509CertVersion;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.NotAfterMode;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.JSON;
import org.xipki.util.TripleState;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Root configuration of the xijson Certprofile.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class X509ProfileType extends ValidableConf {

  private static final Logger LOG = LoggerFactory.getLogger(X509ProfileType.class);

  private Map<String, String> metadata;

  private X509CertVersion version;

  private CertLevel certLevel;

  private CertDomain certDomain = CertDomain.RFC5280;

  private Integer maxSize;

  /**
   * The validity of the certificate to be generated, namely notAfter - notBefore.
   * Examples are:
   * <ul>
   *   <li>5y: 5 years</li>
   *   <li>365d: 365 days</li>
   *   <li>120h: 120 hours</li>
   *   <li>100m: 100 minutes</li>
   *   <li>99991231235959Z: certificate has this UNDEFINED notAfter</li>
   * </ul>
   */
  private String validity;

  /**
   * How CA assigns the notAfter field in the certificate if the requested notAfter is
   * after CA's validity.
   */
  private NotAfterMode notAfterMode;

  /**
   * Value of the notBefore field.
   * <ul>
   *   <li>'current': current time</li>
   *   <li>'midnight'[:timezone]: the next mid night time for the given timezone.
   *        Valid timezones are: GMT+0, GMT+1, ..., GMT+12, GMT-1, ..., GMT-12</li>
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
  private KeypairGenerationType keypairGeneration;

  /**
   * Control how to generate the serial number of certificate
   */
  private String serialNumberMode;

  /**
   * Signature algorithm name. Algorithms supported by the CA are
   * SHA*withECDSA, SHA*withDSA, SHA*withRSA, SHA*withRSAandMGF1, SHA*withPlainECDSA
   * where * is for 1, 224, 256, 384 and 512,
   * and SHA3-*withECDSA, SHA3-*withDSA, SHA3-*withRSA, SHA3-*withRSAandMGF1
   * where * is for 224, 256, 384 and 512.
   */
  private List<String> signatureAlgorithms;

  private List<AlgorithmType> keyAlgorithms;

  private Subject subject;

  private List<SubjectToSubjectAltNameType> subjectToSubjectAltNames;

  private List<ExtensionType> extensions;

  public static X509ProfileType parse(byte[] confBytes) throws CertprofileException {
    Args.notNull(confBytes, "confBytes");
    try {
      X509ProfileType root = JSON.parseObject(confBytes, X509ProfileType.class);
      root.validate();
      return root;
    } catch (InvalidConfException | RuntimeException ex) {
      throw new CertprofileException("parse profile failed, message: " + ex.getMessage(), ex);
    }
  }

  public static X509ProfileType parse(File confFile) throws CertprofileException {
    Args.notNull(confFile, "confFile");
    try {
      X509ProfileType root = JSON.parseObject(confFile, X509ProfileType.class);
      root.validate();
      return root;
    } catch (InvalidConfException | IOException | RuntimeException ex) {
      throw new CertprofileException("parse profile failed, message: " + ex.getMessage(), ex);
    }
  }

  private static X509ProfileType parseAndClose(InputStream confStream) throws CertprofileException {
    try {
      X509ProfileType root = JSON.parseObjectAndClose(confStream, X509ProfileType.class);
      root.validate();
      return root;
    } catch (InvalidConfException | IOException | RuntimeException ex) {
      throw new CertprofileException("parse profile failed, message: " + ex.getMessage(), ex);
    }
  } // method parse

  public X509CertVersion getVersion() {
    return version;
  }

  public void setVersion(X509CertVersion version) {
    this.version = version;
  }

  /**
   * This field is here only to make the JSON deserializer be able to parse old certprofile file.
   * @param serialNumberInReq ignore me.
   */
  @Deprecated
  private void setSerialNumberInReq(boolean serialNumberInReq) {
    if (serialNumberInReq) {
      LOG.warn("ignore setSerialNumberInReq with serialNumberInReq=true");
    }
  }

  public List<String> getSignatureAlgorithms() {
    if (signatureAlgorithms == null) {
      signatureAlgorithms = new LinkedList<>();
    }
    return signatureAlgorithms;
  }

  public void setSignatureAlgorithms(List<String> signatureAlgorithms) {
    this.signatureAlgorithms = signatureAlgorithms;
  }

  public CertLevel getCertLevel() {
    return certLevel;
  }

  public void setCertLevel(CertLevel certLevel) {
    this.certLevel = certLevel;
  }

  public CertDomain getCertDomain() {
    return certDomain;
  }

  public void setCertDomain(CertDomain certDomain) {
    this.certDomain = certDomain;
  }

  public Map<String, String> getMetadata() {
    if (metadata == null) {
      metadata = new HashMap<>();
    }
    return metadata;
  }

  public void setMetadata(Map<String, String> metadata) {
    this.metadata = metadata;
  }

  public String getValidity() {
    return validity;
  }

  public void setValidity(String validity) {
    this.validity = validity;
  }

  public NotAfterMode getNotAfterMode() {
    return notAfterMode;
  }

  public void setNotAfterMode(NotAfterMode notAfterMode) {
    this.notAfterMode = notAfterMode;
  }

  public String getNotBeforeTime() {
    return notBeforeTime;
  }

  public void setNotBeforeTime(String notBeforeTime) {
    this.notBeforeTime = notBeforeTime;
  }

  public KeypairGenerationType getKeypairGeneration() {
    return keypairGeneration;
  }

  public void setKeypairGeneration(KeypairGenerationType keypairGeneration) {
    this.keypairGeneration = keypairGeneration;
  }

  public String getSerialNumberMode() {
    return serialNumberMode;
  }

  public void setSerialNumberMode(String serialNumberMode) {
    this.serialNumberMode = serialNumberMode;
  }

  public List<AlgorithmType> getKeyAlgorithms() {
    if (keyAlgorithms == null) {
      keyAlgorithms = new LinkedList<>();
    }
    return keyAlgorithms;
  }

  public void setKeyAlgorithms(List<AlgorithmType> keyAlgorithms) {
    this.keyAlgorithms = keyAlgorithms;
  }

  public Subject getSubject() {
    return subject;
  }

  public void setSubject(Subject subject) {
    this.subject = subject;
  }

  public List<SubjectToSubjectAltNameType> getSubjectToSubjectAltNames() {
    if (subjectToSubjectAltNames == null) {
      subjectToSubjectAltNames = new LinkedList<>();
    }
    return subjectToSubjectAltNames;
  }

  public void setSubjectToSubjectAltNames(
      List<SubjectToSubjectAltNameType> subjectToSubjectAltNames) {
    this.subjectToSubjectAltNames = subjectToSubjectAltNames;
  }

  public List<ExtensionType> getExtensions() {
    if (extensions == null) {
      extensions = new LinkedList<>();
    }
    return extensions;
  }

  public void setExtensions(List<ExtensionType> extensions) {
    this.extensions = extensions;
  }

  public Integer getMaxSize() {
    return maxSize;
  }

  public void setMaxSize(Integer maxSize) {
    this.maxSize = maxSize;
  }

  public Map<String, ExtensionType> buildExtensions() {
    Map<String, ExtensionType> ret = new HashMap<>();
    for (ExtensionType m : getExtensions()) {
      String type = m.getType().getOid();
      ret.put(type, m);
    }
    return ret;
  }

  public Map<ASN1ObjectIdentifier, KeyParametersOption> toXiKeyAlgorithms()
      throws CertprofileException {
    Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms = new HashMap<>();
    for (AlgorithmType type : this.keyAlgorithms) {
      List<DescribableOid> algIds = type.getAlgorithms();
      List<ASN1ObjectIdentifier> oids = new ArrayList<>(algIds.size());
      for (DescribableOid algId : algIds) {
        ASN1ObjectIdentifier oid = algId.toXiOid();
        if (keyAlgorithms.containsKey(oid)) {
          throw new CertprofileException("duplicate definition of keyAlgorithm " + oid.getId());
        }
        oids.add(oid);
      }

      KeyParametersOption keyParamsOption = (type.getParameters() == null)
          ? KeyParametersOption.ALLOW_ALL : type.getParameters().toXiKeyParametersOption();
      for (ASN1ObjectIdentifier oid : oids) {
        keyAlgorithms.put(oid, keyParamsOption);
      }
    }
    return CollectionUtil.unmodifiableMap(keyAlgorithms);
  } // method toXiKeyAlgorithms

  @Override
  public void validate() throws InvalidConfException {
    notNull(version, "version");
    notNull(certLevel, "certLevel");
    notBlank(validity, "validity");
    notBlank(notBeforeTime, "notBeforeTime");
    notNull(subject, "subject");
    notNull(extensions, "extensions");
    validate(keypairGeneration, subject);
    validate(keyAlgorithms, subjectToSubjectAltNames, extensions);

    Set<String> extnTypes = new HashSet<>();
    for (ExtensionType m : extensions) {
      String type = m.getType().getOid();
      if (!extnTypes.add(type)) {
        throw new InvalidConfException("duplicated definition of extension "
            + ObjectIdentifiers.getName(m.getType().toXiOid()));
      }
    }

  } // method validate

  public Map<ASN1ObjectIdentifier, ExtensionValue> buildConstantExtesions() throws CertprofileException {
    Map<ASN1ObjectIdentifier, ExtensionValue> map = new HashMap<>();

    for (ExtensionType m : getExtensions()) {
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getType().getOid());
      if (Extension.subjectAlternativeName.equals(oid)
          || Extension.subjectInfoAccess.equals(oid)
          || Extension.biometricInfo.equals(oid)) {
        continue;
      }

      if (m.getConstant() == null) {
        continue;
      }

      ASN1Encodable value;
      try {
        value = m.getConstant().toASN1Encodable();
      } catch (InvalidConfException ex) {
        throw new CertprofileException(ex.getMessage(), ex);
      }
      ExtensionValue extension = new ExtensionValue(m.critical(), value);
      map.put(oid, extension);
    }

    if (CollectionUtil.isEmpty(map)) {
      return null;
    }

    return Collections.unmodifiableMap(map);
  } // buildConstantExtesions

  public Map<ASN1ObjectIdentifier, ExtensionControl> buildExtensionControls() throws CertprofileException {
    // Extension controls
    Map<ASN1ObjectIdentifier, ExtensionControl> controls = new HashMap<>();
    for (ExtensionType extn : getExtensions()) {
      ASN1ObjectIdentifier oid = extn.getType().toXiOid();
      if (controls.containsKey(oid)) {
        throw new CertprofileException("duplicated definition of extension " + oid.getId());
      }

      TripleState inReq = extn.getInRequest();
      if (inReq == null) {
        inReq = TripleState.forbidden;
      }

      if (inReq != TripleState.forbidden && extn.getConstant() != null) {
        throw new CertprofileException("constant Extension is not permitted in request");
      }

      controls.put(oid, new ExtensionControl(extn.critical(), extn.required(), inReq));
    }

    return Collections.unmodifiableMap(controls);
  } // method buildExtensionControls

  public static Set<ASN1ObjectIdentifier> toOidSet(List<DescribableOid> oidWithDescTypes) {
    if (CollectionUtil.isEmpty(oidWithDescTypes)) {
      return null;
    }

    Set<ASN1ObjectIdentifier> oids = new HashSet<>();
    for (DescribableOid type : oidWithDescTypes) {
      oids.add(type.toXiOid());
    }
    return Collections.unmodifiableSet(oids);
  } // method toOidSet

}
