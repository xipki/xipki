// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.ctrl.CertDomain;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.RdnType;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.ca.certprofile.xijsonv1.conf.extn.V1KeyUsages;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.security.KeySpec;
import org.xipki.security.KeyUsage;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.util.EcCurveEnum;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.extra.exception.CertprofileException;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Root configuration of the xijson v1 Certprofile.
 *
 * @author Lijun Liao (xipki)
 */

public class V1XijsonCertprofileType {

  private static final Logger LOG =
      LoggerFactory.getLogger(V1XijsonCertprofileType.class);

  private Map<String, String> metadata;

  private final CertLevel certLevel;

  private CertDomain certDomain = CertDomain.RFC5280;

  private Integer maxSize;

  /**
   * The validity of the certificate to be generated, namely
   * notAfter - notBefore.
   * Examples are:
   * <ul>
   *   <li>5y: 5 years</li>
   *   <li>365d: 365 days</li>
   *   <li>120h: 120 hours</li>
   *   <li>100m: 100 minutes</li>
   *   <li>99991231235959Z: certificate has this UNDEFINED notAfter</li>
   * </ul>
   */
  private final String validity;

  /**
   * How CA assigns the notAfter field in the certificate if the requested
   * notAfter is after CA's validity.
   */
  private ValidityMode notAfterMode;

  /**
   * Value of the notBefore field.
   * <ul>
   *   <li>'current': current time</li>
   *   <li>'midnight'[:timezone]: the next midnight time for the given
   *        timezone. Valid timezones are: GMT+0, GMT+1, ..., GMT+12,
   *        GMT-1, ..., GMT-12</li>
   *   <li>'+'offset: offset after current time</li>
   *   <li>'-'offset: before after current time, In the current implementation,
   *        offset of maximal 10 minutes is allowed.
   *        The offset must have the following suffixes:
   *        <ul>
   *          <li>'d' for day, e.g. '2d' for 2 days,</li>
   *          <li>'h' for day, e.g. '2h' for 2 hours,</li>
   *          <li>'m' for day, e.g. '2m' for 2 minutes,</li>
   *          <li>'s' for day, e.g. '2s' for 2 seconds.</li>
   *        </ul>
   *   </li>
   * </ul>
   */
  private final String notBeforeTime;

  /**
   * Control how CA will generate the keypair for the certificate.
   * Defaults to forbidden.
   */
  private V1KeypairGenerationType keypairGeneration;

  /**
   * Signature algorithm name. Algorithms supported by the CA are
   * SHA*withECDSA, SHA*withDSA, SHA*withRSA, SHA*withRSAandMGF1,
   * SHA*withPlainECDSA,
   * where * is for 1, 224, 256, 384 and 512,
   * and SHA3-*withECDSA, SHA3-*withDSA, SHA3-*withRSA,
   * SHA3-*withRSAandMGF1,
   * where * is for 224, 256, 384 and 512.
   */
  private List<String> signatureAlgorithms;

  private List<V1AlgorithmType> keyAlgorithms;

  private final V1Subject subject;

  private List<V1SubjectToSubjectAltNameType> subjectToSubjectAltNames;

  private final List<V1ExtensionType> extensions;

  public V1XijsonCertprofileType(
      CertLevel certLevel, String validity,
      String notBeforeTime, V1Subject subject,
      List<V1ExtensionType> extensions) {
    this.certLevel = Args.notNull(certLevel, "certLevel");
    this.validity = Args.notBlank(validity, "validity");
    this.notBeforeTime = Args.notBlank(notBeforeTime, "notBeforeTime");
    this.subject = Args.notNull(subject, "subject");
    this.extensions = Args.notNull(extensions, "extensions");

    Set<String> extnTypes = new HashSet<>();
    for (V1ExtensionType m : extensions) {
      String type = m.type().getOid();
      if (!extnTypes.add(type)) {
        throw new IllegalArgumentException(
            "duplicated definition of extension " + m.type().getOid());
      }
    }
  }

  public static V1XijsonCertprofileType parse(byte[] confBytes)
      throws CertprofileException {
    Args.notNull(confBytes, "confBytes");
    try {
      return parse(JsonParser.parseMap(confBytes, true));
    } catch (RuntimeException | CodecException ex) {
      throw new CertprofileException(
          "parse profile failed, message: " + ex.getMessage(), ex);
    }
  }

  public static V1XijsonCertprofileType parse(JsonMap json)
      throws CodecException {
    JsonList list = json.getNnList("extensions");
    List<V1ExtensionType> extensions = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      extensions.add(V1ExtensionType.parse(v));
    }

    V1XijsonCertprofileType ret = new V1XijsonCertprofileType(
        json.getEnum("certLevel", CertLevel.class),
        json.getString("validity"),
        json.getString("notBeforeTime"),
        V1Subject.parse(json.getNnMap("subject")),
        extensions);

    ret.metadata = json.getStringMap("metadata");

    CertDomain certDomain = json.getEnum("certDomain", CertDomain.class);
    if (certDomain != null) {
      ret.certDomain = certDomain;
    }

    ret.maxSize = json.getInt("maxSize");

    String str = json.getString("notAfterMode");
    if (str != null) {
      ret.notAfterMode = ValidityMode.forName(str);
    }

    JsonMap map = json.getMap("keypairGeneration");
    if (map != null) {
      ret.keypairGeneration = V1KeypairGenerationType.parse(map);
    }

    ret.signatureAlgorithms = json.getStringList("signatureAlgorithms");

    list = json.getList("keyAlgorithms");
    if (list != null) {
      ret.keyAlgorithms = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        ret.keyAlgorithms.add(V1AlgorithmType.parse(v));
      }
    }

    list = json.getList("subjectToSubjectAltNames");
    if (list != null) {
      List<V1SubjectToSubjectAltNameType> subjectToSubjectAltNames =
          new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        subjectToSubjectAltNames.add(V1SubjectToSubjectAltNameType.parse(v));
      }
      ret.subjectToSubjectAltNames = subjectToSubjectAltNames;
    }

    Boolean b = json.getBool("serialNumberInReq");
    if (b != null && b) {
      LOG.warn("ignore serialNumberInReq=true");
    }

    return ret;
  }

  private List<KeySpec> getKeyAlgorithms(
      CertLevel certLevel, CertDomain certDomain, List<KeyUsage> keyUsages)
      throws CertprofileException {
    Set<KeySpec> v2 = new HashSet<>(keyAlgorithms.size());

    for (V1AlgorithmType t : keyAlgorithms) {
      boolean isRsa = false;
      boolean isWeierstraussEC = false;

      for (DescribableOid doid : t.algorithms()) {
        ASN1ObjectIdentifier oid = doid.oid();

        if (OIDs.Algo.id_rsaEncryption.equals(oid)) {
          isRsa = true;
        } else if (OIDs.Algo.id_ecPublicKey.equals(oid)) {
          isWeierstraussEC = true;
        } else if (OIDs.Curve.id_ED25519.equals(oid)) {
          addKeySpec(v2, KeySpec.ED25519);
        } else if (OIDs.Curve.id_ED448.equals(oid)) {
          addKeySpec(v2, KeySpec.ED448);
        } else if (OIDs.Curve.id_X25519.equals(oid)) {
          addKeySpec(v2, KeySpec.X25519);
        } else if (OIDs.Curve.id_X448.equals(oid)) {
          addKeySpec(v2, KeySpec.X448);
        } else if (OIDs.Algo.id_ml_dsa_44.equals(oid)) {
          addKeySpec(v2, KeySpec.MLDSA44);
        } else if (OIDs.Algo.id_ml_dsa_65.equals(oid)) {
          addKeySpec(v2, KeySpec.MLDSA65);
        } else if (OIDs.Algo.id_ml_dsa_87.equals(oid)) {
          addKeySpec(v2, KeySpec.MLDSA87);
        } else if (OIDs.Algo.id_ml_kem_512.equals(oid)) {
          addKeySpec(v2, KeySpec.MLKEM512);
        } else if (OIDs.Algo.id_ml_kem_768.equals(oid)) {
          addKeySpec(v2, KeySpec.MLKEM768);
        } else if (OIDs.Algo.id_ml_kem_1024.equals(oid)) {
          addKeySpec(v2, KeySpec.MLKEM1024);
        } else {
          LOG.warn("ignore unknown key type {}", oid.getId());
        }
      }

      V1KeyParametersType keyParams = t.parameters();

      if (isRsa) {
        V1KeyParametersType.RsaParametersType params =
            (keyParams == null) ? null : keyParams.rsa();

        if (params == null || params.modulus() == null) {
          addKeySpec(v2, KeySpec.RSA2048, KeySpec.RSA3072, KeySpec.RSA4096);
        } else {
          List<Integer> modulusSizes = params.modulus();

          if (modulusSizes.remove((Integer) 2048)) {
            addKeySpec(v2, KeySpec.RSA2048);
          }

          if (modulusSizes.remove((Integer) 3072)) {
            addKeySpec(v2, KeySpec.RSA3072);
          }

          if (modulusSizes.remove((Integer) 4096)) {
            addKeySpec(v2, KeySpec.RSA4096);
          }

          if (!modulusSizes.isEmpty()) {
            LOG.warn("ignore RSA key sizes {}", modulusSizes);
          }
        }
      } else if (isWeierstraussEC) {
        V1KeyParametersType.EcParametersType params =
            (keyParams == null) ? null : keyParams.ec();

        if (params == null || params.curves() == null
            || params.curves().isEmpty()) {
          addKeySpec(v2, KeySpec.SECP256R1, KeySpec.SECP384R1,
              KeySpec.SECP521R1, KeySpec.BRAINPOOLP256R1,
              KeySpec.BRAINPOOLP384R1, KeySpec.BRAINPOOLP512R1,
              KeySpec.SM2P256V1, KeySpec.FRP256V1);
        } else {
          for (DescribableOid curveOid : params.curves()) {
            EcCurveEnum curveEnum = EcCurveEnum.ofOid(curveOid.oid());
            if (curveEnum == null) {
              LOG.warn("ignore unknown EC curve {}", curveOid.oid());
              continue;
            }

            KeySpec keySpec = KeySpec.ofEcCurve(curveEnum);
            addKeySpec(v2, keySpec);
          }
        }
      }
    }

    // TODO: remove me
    // If only RSA is allowed
    boolean onlyRsa = true;
    for (KeySpec k : v2) {
      onlyRsa = k == KeySpec.RSA2048 || k == KeySpec.RSA3072
          || k == KeySpec.RSA4096;
      if (!onlyRsa) {
        break;
      }
    }

    boolean onlySingle = v2.size() == 1;

    if (!onlySingle && !onlyRsa && certDomain != CertDomain.CABForumBR) {
      Set<KeySpec> availableSpecs = new HashSet<>(List.of(KeySpec.values()));
      if (certLevel != CertLevel.EndEntity) {
        // encrypt-only key types are not allowed in CA certificates
        availableSpecs.remove(KeySpec.X25519);
        availableSpecs.remove(KeySpec.X448);
        availableSpecs.remove(KeySpec.MLKEM512);
        availableSpecs.remove(KeySpec.MLKEM768);
        availableSpecs.remove(KeySpec.MLKEM1024);
      } else {
        if (v2.contains(KeySpec.ED25519) && !v2.contains(KeySpec.X25519)) {
          // remove encrypt-only key types
          availableSpecs.remove(KeySpec.X25519);
          availableSpecs.remove(KeySpec.X448);
          availableSpecs.remove(KeySpec.MLKEM512);
          availableSpecs.remove(KeySpec.MLKEM768);
          availableSpecs.remove(KeySpec.MLKEM1024);
        }
      }

      v2.addAll(availableSpecs);
    }

    if (v2.isEmpty()) {
      throw new CertprofileException(
          "could not convert the allowed key algorithms");
    }

    if (keyUsages == null) {
      return toSortedKeySpecs(v2);
    }

    boolean withEncryptUsages = false;
    boolean withSignUsages = false;
    for (KeyUsage ku : keyUsages) {
      switch (ku) {
        case digitalSignature:
        case contentCommitment:
        case cRLSign:
        case keyCertSign:
          withSignUsages = true;
          break;
        case dataEncipherment:
        case decipherOnly:
        case keyAgreement:
        case encipherOnly:
        case keyEncipherment:
          withEncryptUsages = true;
          break;
      }

      if (withSignUsages && withEncryptUsages) {
        break;
      }
    }

    if (withSignUsages && withEncryptUsages) {
      return toSortedKeySpecs(v2);
    }

    if (!withSignUsages) {
      // remove key type for sign only
      Set<KeySpec> newSpecs = new HashSet<>();
      for (KeySpec ks : v2) {
        if (!(ks.isMldsa() || ks.isEdwardsEC())) {
          newSpecs.add(ks);
        }
      }

      v2 = newSpecs;
    }

    if (!withEncryptUsages) {
      // remove key type for encrypt only
      Set<KeySpec> newSpecs = new HashSet<>();
      for (KeySpec ks : v2) {
        if (!(ks.isMlkem() || ks.isMontgomeryEC())) {
          newSpecs.add(ks);
        }
      }

      v2 = newSpecs;
    }

    return toSortedKeySpecs(v2);
  }

  public static List<KeySpec> toSortedKeySpecs(Collection<KeySpec> keySpecs) {
    List<KeySpec> list = new ArrayList<>(keySpecs);
    Collections.sort(list);
    return list;
  }

  private List<SignAlgo> getSignatureAlgorithms() {
    List<SignAlgo> v2 = new ArrayList<>(signatureAlgorithms.size());

    for (String a : signatureAlgorithms) {
      SignAlgo sc;
      try {
        sc = SignAlgo.getInstance(a);
        if (sc == null) {
          LOG.warn("ignore unknown SignAlgo '{}'", a);
        }
      } catch (NoSuchAlgorithmException e) {
        LOG.warn("ignore unknown signature algorithm '{}'", a);
        continue;
      }

      if (sc != null && !v2.contains(sc)) {
        v2.add(sc);
      }
    }

    return v2;
  }

  public XijsonCertprofileType toV2() throws CertprofileException {
    XijsonCertprofileType v2 = new XijsonCertprofileType();

    v2.setCertDomain(certDomain);
    v2.setCertLevel(certLevel);
    v2.setMetadata(metadata);
    v2.setMaxSize(maxSize);
    v2.setNotBeforeTime(notBeforeTime);
    v2.setNotAfterMode(notAfterMode);
    v2.setValidity("99991231235959Z".equalsIgnoreCase(validity)
        ? "UNDEFINED" : validity);

    // keys
    if (keypairGeneration != null) {
      v2.setKeypairGeneration(keypairGeneration.toV2());
    }

    if (keyAlgorithms != null) {
      List<KeyUsage> keyUsages = null;
      for (V1ExtensionType ext : extensions) {
        if (!ext.type().getOid().equals(OIDs.Extn.keyUsage.getId())) {
          continue;
        }

        keyUsages = new LinkedList<>();
        for (V1KeyUsages.Usage usage : ext.keyUsage().usages()) {
          keyUsages.add(KeyUsage.getKeyUsage(usage.value()));
        }
      }

      v2.setKeyAlgorithms(getKeyAlgorithms(certLevel, certDomain, keyUsages));

    }

    if (signatureAlgorithms != null) {
      v2.setSignatureAlgorithms(getSignatureAlgorithms());
    }

    // subject
    v2.setKeepExtensionsOrder(subject.keepRdnOrder());
    List<RdnType> rdns = new ArrayList<>(10);
    v2.setSubject(rdns);

    for (V1Subject.V1RdnType v1Rdn : subject.rdns()) {
      RdnType attr = v1Rdn.toV2();
      rdns.add(attr);
    }

    if (subjectToSubjectAltNames != null) {
      for (V1SubjectToSubjectAltNameType c : subjectToSubjectAltNames) {
        ASN1ObjectIdentifier oid = c.source().oid();

        RdnType rdn = null;
        for (RdnType m : rdns) {
          if (oid.equals(m.type().oid())) {
            rdn = m;
            break;
          }
        }

        if (rdn == null) {
          rdn = new RdnType(AttributeType.ofOid(oid), null, 0, 0);
          rdns.add(rdn);
        }
        rdn.setToSAN(c.target());
      }
    }

    // extensions
    List<ExtensionType> extensionTypes = new ArrayList<>(extensions.size());
    v2.setExtensions(extensionTypes);

    for (V1ExtensionType v1 : extensions) {
      extensionTypes.add(v1.toV2(v2.keyAlgorithms()));
    }

    return v2;
  }

  private static void addKeySpec(Set<KeySpec> list, KeySpec... keySpecs) {
    list.addAll(Arrays.asList(keySpecs));
  }

}
