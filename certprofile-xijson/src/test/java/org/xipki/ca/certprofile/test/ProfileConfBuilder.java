/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.certprofile.test;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.ca.api.CertprofileValidator;
import org.xipki.ca.api.profile.Certprofile.CertDomain;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.api.profile.Certprofile.X509CertVersion;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.*;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.ca.certprofile.xijson.conf.KeyParametersType.DsaParametersType;
import org.xipki.ca.certprofile.xijson.conf.KeyParametersType.EcParametersType;
import org.xipki.ca.certprofile.xijson.conf.KeyParametersType.RsaParametersType;
import org.xipki.ca.certprofile.xijson.conf.KeypairGenerationType.KeyType;
import org.xipki.ca.certprofile.xijson.conf.Subject.RdnType;
import org.xipki.ca.certprofile.xijson.conf.Subject.ValueType;
import org.xipki.security.EdECConstants;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Builder to create xijson configuration.
 *
 * @author Lijun Liao
 */

public class ProfileConfBuilder extends ExtensionConfBuilder {

  protected static final String REGEX_SN = ":NUMBER";

  protected static final String REGEX_FQDN = ":FQDN";

  protected static final Set<ASN1ObjectIdentifier> NOT_IN_SUBJECT_RDNS;

  static {
    NOT_IN_SUBJECT_RDNS = new HashSet<>();
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_ICRegistrationNumber);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_IdentityCode);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_InsuranceNumber);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_OrganizationCode);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_GMT_0015_TaxationNumber);
    NOT_IN_SUBJECT_RDNS.add(Extn.id_extension_admission);
  } // method static

  protected static void marshall(X509ProfileType profile, String filename, boolean validate) {
    try {
      Path path = Paths.get("tmp", filename);
      IoUtil.mkdirsParent(path);
      try (OutputStream out = Files.newOutputStream(path)) {
        JSON.writeJSONString(out, profile,
            SerializerFeature.PrettyFormat, SerializerFeature.SortField,
            SerializerFeature.DisableCircularReferenceDetect);
      }

      if (validate) {
        X509ProfileType profileConf;
        // Test by deserializing
        try (InputStream is = Files.newInputStream(path)) {
          profileConf = X509ProfileType.parse(is);
        }
        XijsonCertprofile profileObj = new XijsonCertprofile();
        profileObj.initialize(profileConf);
        profileObj.close();

        CertprofileValidator.validate(profileObj);
        System.out.println("Generated certprofile in " + filename);
      }
    } catch (Exception ex) {
      System.err.println("Error while generating certprofile in " + filename);
      ex.printStackTrace();
    }

  } // method marshal

  protected static X509ProfileType getBaseCabSubscriberProfile(String desc) {
    X509ProfileType profile = getBaseCabProfile(desc, CertLevel.EndEntity, "397d");

    //profile.setNotAfterMode(NotAfterMode.BY_CA);

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(DN.CN));
    s2sType.setTarget(GeneralNameTag.DNSName);

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false, null));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false, null));
    last(list).setCrlDistributionPoints(createCrlDistibutoionPoints());

    // Extensions - SubjectAltNames
    list.add(createExtension(Extension.subjectAlternativeName, true, false));
    GeneralNameType san = new GeneralNameType();
    last(list).setSubjectAltName(san);
    san.addTags(GeneralNameTag.DNSName, GeneralNameTag.IPAddress);

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment},
        null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth},
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}));

    // Extensions - CTLog
    list.add(createExtension(Extn.id_SCTs, true, false));

    return profile;
  } // method getBaseCabSubscriberProfile

  protected static RdnType createRdn(ASN1ObjectIdentifier type, int min, int max) {
    return createRdn(type, min, max, null, null, null);
  }

  protected static RdnType createRdn(ASN1ObjectIdentifier type, int min, int max,
      String regex, String prefix, String suffix) {
    return createRdn(type, min, max, regex, prefix, suffix, null);
  }

  protected static RdnType createRdn(ASN1ObjectIdentifier type, int min, int max,
      String regex, String prefix, String suffix, String group) {
    return createRdn(type, min, max, regex, prefix, suffix, group, null);
  }

  protected static RdnType createRdn(ASN1ObjectIdentifier type, int min, int max,
      String regex, String prefix, String suffix, String group, ValueType value) {
    RdnType ret = new RdnType();
    ret.setType(createOidType(type));
    ret.setMinOccurs(min);
    ret.setMaxOccurs(max);

    if (regex != null) {
      ret.setRegex(regex);
    }

    if (StringUtil.isNotBlank(prefix)) {
      ret.setPrefix(prefix);
    }

    if (StringUtil.isNotBlank(suffix)) {
      ret.setSuffix(suffix);
    }

    if (StringUtil.isNotBlank(group)) {
      ret.setGroup(group);
    }

    if (value != null) {
      ret.setValue(value);
    }

    if (NOT_IN_SUBJECT_RDNS.contains(type)) {
      ret.setNotInSubject(Boolean.TRUE);
    }

    return ret;
  } // method createRdn

  protected static RdnType createRdn(ASN1ObjectIdentifier type,
      String regex, String group, ValueType value) {
    RdnType ret = new RdnType();
    ret.setType(createOidType(type));
    ret.setMinOccurs(1);
    ret.setMaxOccurs(1);
    ret.setValue(value);

    if (regex != null) {
      ret.setRegex(regex);
    }

    if (StringUtil.isNotBlank(group)) {
      ret.setGroup(group);
    }

    return ret;
  } // method createRdn

  protected static X509ProfileType getBaseCabProfile(String description, CertLevel certLevel,
      String validity) {
    return getBaseCabProfile(description, certLevel, validity, false);
  }

  protected static X509ProfileType getBaseCabProfile(String description, CertLevel certLevel,
      String validity, boolean useMidnightNotBefore) {
    X509ProfileType profile = new X509ProfileType();

    profile.setMetadata(createDescription(description));

    profile.setCertDomain(CertDomain.CABForumBR);
    profile.setCertLevel(certLevel);
    profile.setMaxSize(6000 * 3 / 4);
    profile.setVersion(X509CertVersion.v3);
    profile.setValidity(validity);
    profile.setNotBeforeTime(useMidnightNotBefore ? "midnight" : "current");

    profile.setSerialNumberInReq(false);

    if (certLevel == CertLevel.EndEntity) {
      profile.setKeypairGeneration(new KeypairGenerationType());
      profile.getKeypairGeneration().setInheritCA(true);
    }

    // SignatureAlgorithms
    List<String> algos = new LinkedList<>();
    profile.setSignatureAlgorithms(algos);

    String[] sigHashAlgos = new String[]{"SHA512", "SHA384", "SHA256"};

    String[] algoPart2s = new String[]{"withRSA", "withDSA", "withECDSA", "withRSAandMGF1"};
    for (String part2 : algoPart2s) {
      for (String hashAlgo : sigHashAlgos) {
        algos.add(hashAlgo + part2);
      }
    }

    // Subject
    Subject subject = new Subject();
    profile.setSubject(subject);
    subject.setKeepRdnOrder(false);

    // Key
    profile.setKeyAlgorithms(createCabKeyAlgorithms());

    return profile;
  } // method getBaseCabProfile

  protected static X509ProfileType getBaseProfile(String description, CertLevel certLevel,
                                                   String validity) {
    return  getBaseProfile(description, certLevel, validity, true);
  }

  protected static X509ProfileType getBaseProfile(String description, CertLevel certLevel,
      String validity, boolean withEddsa) {
    return getBaseProfile(description, certLevel, validity, false, withEddsa);
  }

  protected static X509ProfileType getBaseProfile(String description, CertLevel certLevel,
      String validity, boolean useMidnightNotBefore, boolean withEddsa) {
    X509ProfileType profile = new X509ProfileType();

    profile.setMetadata(createDescription(description));

    profile.setCertLevel(certLevel);
    profile.setMaxSize(4500);
    profile.setVersion(X509CertVersion.v3);
    profile.setValidity(validity);
    profile.setNotBeforeTime(useMidnightNotBefore ? "midnight" : "current");

    profile.setSerialNumberInReq(false);

    if (certLevel == CertLevel.EndEntity) {
      profile.setKeypairGeneration(new KeypairGenerationType());
      profile.getKeypairGeneration().setInheritCA(true);
    }

    // SignatureAlgorithms
    List<String> algos = new LinkedList<>();
    profile.setSignatureAlgorithms(algos);

    String[] sigHashAlgos = new String[]{"SHA3-512", "SHA3-384", "SHA3-256", "SHA3-224",
      "SHA512", "SHA384", "SHA256", "SHA1"};

    String[] algoPart2s = new String[]{"withRSA", "withDSA", "withECDSA", "withRSAandMGF1"};
    for (String part2 : algoPart2s) {
      for (String hashAlgo : sigHashAlgos) {
        algos.add(hashAlgo + part2);
      }
    }

    String part2 = "withPlainECDSA";
    for (String hashAlgo : sigHashAlgos) {
      if (!hashAlgo.startsWith("SHA3-")) {
        algos.add(hashAlgo + part2);
      }
    }

    algos.add("SM3withSM2");
    algos.add("Ed25519");
    algos.add("Ed448");
    algos.add("SHAKE128withRSAPSS");
    algos.add("SHAKE256withRSAPSS");
    algos.add("SHAKE128withECDSA");
    algos.add("SHAKE256withECDSA");

    // Subject
    Subject subject = new Subject();
    profile.setSubject(subject);
    subject.setKeepRdnOrder(false);

    ASN1ObjectIdentifier[] curveIds = (CertLevel.EndEntity != certLevel) ? null :
      new ASN1ObjectIdentifier[] {
              SECObjectIdentifiers.secp256r1,
              SECObjectIdentifiers.secp384r1,
              SECObjectIdentifiers.secp521r1,
              TeleTrusTObjectIdentifiers.brainpoolP256r1,
              TeleTrusTObjectIdentifiers.brainpoolP256r1,
              TeleTrusTObjectIdentifiers.brainpoolP384r1,
              TeleTrusTObjectIdentifiers.brainpoolP512r1,
              GMObjectIdentifiers.sm2p256v1};

    // Key
    profile.setKeyAlgorithms(createKeyAlgorithms(curveIds, certLevel, withEddsa));

    return profile;
  } // method getBaseProfile

  protected static X509ProfileType getEeBaseProfileForEdwardsOrMontgomeryCurves(String description,
      String validity, boolean edwards, boolean curve25519) {
    X509ProfileType profile = new X509ProfileType();

    profile.setMetadata(createDescription(description));

    profile.setCertLevel(CertLevel.EndEntity);
    profile.setMaxSize(4500);
    profile.setVersion(X509CertVersion.v3);
    profile.setValidity(validity);
    profile.setNotBeforeTime("current");

    profile.setSerialNumberInReq(false);

    KeypairGenerationType kpGen = new KeypairGenerationType();
    profile.setKeypairGeneration(kpGen);
    KeyType keyType;
    ASN1ObjectIdentifier algorithm;
    if (edwards) {
      keyType = curve25519 ? KeyType.ed25519 : KeyType.ed448;
      algorithm = curve25519 ? EdECConstants.id_ED25519 : EdECConstants.id_ED448;
    } else {
      keyType = curve25519 ? KeyType.x25519 : KeyType.x448;
      algorithm = curve25519 ? EdECConstants.id_X25519 : EdECConstants.id_X448;
    }
    kpGen.setAlgorithm(createOidType(algorithm));
    kpGen.setKeyType(keyType);

    // SignatureAlgorithm
    List<String> algos = new LinkedList<>();
    profile.setSignatureAlgorithms(algos);
    algos.add("Ed25519");
    algos.add("Ed448");

    // Subject
    Subject subject = new Subject();
    profile.setSubject(subject);
    subject.setKeepRdnOrder(false);

    // KeyUsage

    KeyUsage[] usages = edwards
      ? new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.contentCommitment}
      : new KeyUsage[]{KeyUsage.keyAgreement};

    List<AlgorithmType> keyAlgorithms = createEdwardsOrMontgomeryKeyAlgorithms(
        edwards, curve25519, !curve25519);

    profile.setKeyAlgorithms(keyAlgorithms);
    List<ExtensionType> extensions = profile.getExtensions();
    extensions.add(createExtension(Extension.keyUsage, true, true));
    last(extensions).setKeyUsage(createKeyUsage(usages, null));

    return profile;
  } // method getEeBaseProfileForEdwardsOrMontgomeryCurves

  protected static List<AlgorithmType> createCabKeyAlgorithms() {
    List<AlgorithmType> list = new LinkedList<>();

    // RSA
    list.addAll(createRSAKeyAlgorithms());

    // DSA
    list.add(new AlgorithmType());
    last(list).getAlgorithms().add(createOidType(X9ObjectIdentifiers.id_dsa, "DSA"));
    last(list).setParameters(new KeyParametersType());

    DsaParametersType dsaParams = new DsaParametersType();
    last(list).getParameters().setDsa(dsaParams);

    List<Range> plengths = new LinkedList<>();
    dsaParams.setPlengths(plengths);

    plengths.add(createRange(2048));
    plengths.add(createRange(3072));

    List<Range> qlengths = new LinkedList<>();
    dsaParams.setQlengths(qlengths);
    qlengths.add(createRange(224));
    qlengths.add(createRange(256));

    // EC
    list.add(new AlgorithmType());

    last(list).getAlgorithms().add(createOidType(X9ObjectIdentifiers.id_ecPublicKey, "EC"));
    last(list).setParameters(new KeyParametersType());

    EcParametersType ecParams = new EcParametersType();
    last(list).getParameters().setEc(ecParams);

    ASN1ObjectIdentifier[] curveIds = new ASN1ObjectIdentifier[] {
            SECObjectIdentifiers.secp256r1,
            SECObjectIdentifiers.secp384r1,
            SECObjectIdentifiers.secp521r1};
    List<DescribableOid> curves = new LinkedList<>();
    ecParams.setCurves(curves);

    for (ASN1ObjectIdentifier curveId : curveIds) {
      String name = AlgorithmUtil.getCurveName(curveId);
      curves.add(createOidType(curveId, name));
    }

    ecParams.setPointEncodings(Collections.singletonList(((byte) 4)));

    return list;
  } // method createCabKeyAlgorithms

  protected static List<AlgorithmType> createKeyAlgorithms(
      ASN1ObjectIdentifier[] curveIds, CertLevel certLevel, boolean withEddsa) {
    List<AlgorithmType> list = new LinkedList<>();

    // RSA
    list.addAll(createRSAKeyAlgorithms());

    // DSA
    list.add(new AlgorithmType());
    last(list).getAlgorithms().add(createOidType(X9ObjectIdentifiers.id_dsa, "DSA"));
    last(list).setParameters(new KeyParametersType());

    DsaParametersType dsaParams = new DsaParametersType();
    last(list).getParameters().setDsa(dsaParams);

    List<Range> plengths = new LinkedList<>();
    dsaParams.setPlengths(plengths);

    plengths.add(createRange(1024));
    plengths.add(createRange(2048));
    plengths.add(createRange(3072));

    List<Range> qlengths = new LinkedList<>();
    dsaParams.setQlengths(qlengths);
    qlengths.add(createRange(160));
    qlengths.add(createRange(224));
    qlengths.add(createRange(256));

    // EC
    list.add(new AlgorithmType());

    last(list).getAlgorithms().add(createOidType(X9ObjectIdentifiers.id_ecPublicKey, "EC"));
    last(list).setParameters(new KeyParametersType());

    EcParametersType ecParams = new EcParametersType();
    last(list).getParameters().setEc(ecParams);

    if (curveIds != null && curveIds.length > 0) {
      List<DescribableOid> curves = new LinkedList<>();
      ecParams.setCurves(curves);

      for (ASN1ObjectIdentifier curveId : curveIds) {
        String name = AlgorithmUtil.getCurveName(curveId);
        curves.add(createOidType(curveId, name));
      }
    }

    ecParams.setPointEncodings(Collections.singletonList(((byte) 4)));

    // EdDSA
    if (withEddsa) {
      list.addAll(createEdwardsOrMontgomeryKeyAlgorithms(true, true, true));
    }

    return list;
  } // method createKeyAlgorithms

  protected static List<AlgorithmType> createEdwardsOrMontgomeryKeyAlgorithms(
      boolean edwards, boolean curve25519, boolean curve448) {
    List<AlgorithmType> list = new LinkedList<>();

    List<ASN1ObjectIdentifier> oids = new LinkedList<>();
    if (edwards) {
      if (curve25519) {
        oids.add(EdECConstants.id_ED25519);
      }

      if (curve448) {
        oids.add(EdECConstants.id_ED448);
      }
    } else {
      if (curve25519) {
        oids.add(EdECConstants.id_X25519);
      }

      if (curve448) {
        oids.add(EdECConstants.id_X448);
      }
    }

    for (ASN1ObjectIdentifier oid : oids) {
      list.add(new AlgorithmType());
      last(list).getAlgorithms().add(createOidType(oid));
    }

    return list;
  } // method createEdwardsOrMontgomeryKeyAlgorithms

  // CHECKSTYLE:SKIP
  protected static List<AlgorithmType> createRSAKeyAlgorithms() {
    List<AlgorithmType> list = new LinkedList<>();

    list.add(new AlgorithmType());
    last(list).getAlgorithms().add(createOidType(PKCSObjectIdentifiers.rsaEncryption, "RSA"));
    last(list).setParameters(new KeyParametersType());

    RsaParametersType rsaParams = new RsaParametersType();
    last(list).getParameters().setRsa(rsaParams);

    rsaParams.getModulusLengths().add(createRange(2048));
    rsaParams.getModulusLengths().add(createRange(3072));
    rsaParams.getModulusLengths().add(createRange(4096));

    return list;
  } // method createRSAKeyAlgorithms

  protected static Range createRange(int size) {
    return createRange(size, size);
  }

  protected static <T> T last(List<T> list) {
    if (list == null || list.isEmpty()) {
      return null;
    } else {
      return list.get(list.size() - 1);
    }

  } // method last

}
