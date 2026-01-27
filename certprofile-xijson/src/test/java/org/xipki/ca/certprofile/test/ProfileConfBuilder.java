// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.xipki.ca.api.CertprofileValidator;
import org.xipki.ca.api.profile.ctrl.CertDomain;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.ca.api.profile.id.ExtendedKeyUsageID;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.ca.certprofile.xijson.conf.RdnType;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.security.KeyUsage;
import org.xipki.security.SignSpec;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.io.IoUtil;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Builder to create json configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class ProfileConfBuilder extends ExtensionConfBuilder {

  protected static final String REGEX_FQDN = ":FQDN";

  protected static void marshall(XijsonCertprofileType profile,
                                 String filename, boolean validate) {
    // TODO: consider validate
    //validate = false;
    try {
      Path path = Paths.get("tmp", filename);
      IoUtil.mkdirsParent(path);
      try (OutputStream out = Files.newOutputStream(path)) {
        String json = JsonBuilder.toPrettyJson(profile.toCodec());
        out.write(json.getBytes(StandardCharsets.UTF_8));
      }

      if (validate) {
        XijsonCertprofileType profileConf =
            XijsonCertprofileType.parse(path.toFile());

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

  protected static XijsonCertprofileType getBaseCabSubscriberProfile(
      String desc) {
    XijsonCertprofileType profile =
        getBaseCabProfile(desc, CertLevel.EndEntity, "397d");

    //profile.setNotAfterMode(NotAfterMode.BY_CA);

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));

    // Extensions - SubjectAltNames
    list.add(createExtension(ExtensionID.subjectAltName, true, false));
    GeneralNameType san = new GeneralNameType(
        Arrays.asList(GeneralNameTag.DNSName, GeneralNameTag.IPAddress));
    last(list).setSubjectAltName(san);

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment},
        null));

    // Extensions - extenedKeyUsage
    list.add(createExtension(ExtensionID.extKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.serverAuth},
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.clientAuth}));

    // Extensions - CTLog
    list.add(createExtension(ExtensionID.signedCertificateTimestampList,
        true, false));

    return profile;
  } // method getBaseCabSubscriberProfile

  protected static RdnType rdn(AttributeType type) {
    return rdn(type, 1, 1, null, null);
  }

  protected static RdnType rdn01(AttributeType type) {
    return rdn(type, 0, 1, null, null);
  }

  protected static RdnType rdn(AttributeType type, int min, int max) {
    return rdn(type, min, max, null, null);
  }

  protected static RdnType rdn(
      AttributeType type, int min, int max, String regex) {
    return rdn(type, min, max, regex, null);
  }

  protected static RdnType rdn(
      AttributeType type, int min, int max, String regex, String value) {
    return rdn(type, min, max, regex, value, null);
  }

  protected static RdnType rdn(
      AttributeType type, int min, int max, String regex, String value,
      GeneralNameTag toSAN) {
    RdnType ret = new RdnType(type, value, min, max);
    ret.setRegex(regex);
    ret.setToSAN(toSAN);
    return ret;
  } // method createRdn

  protected static RdnType rdn(
      AttributeType type, String regex, String value) {
    RdnType ret = new RdnType(type, value, null, null);
    ret.setRegex(regex);
    return ret;
  } // method createRdn

  protected static XijsonCertprofileType getBaseCabProfile(
      String description, CertLevel certLevel, String validity) {
    XijsonCertprofileType profile = new XijsonCertprofileType();

    profile.setMetadata(createDescription(description));

    profile.setCertDomain(CertDomain.CABForumBR);
    profile.setCertLevel(certLevel);
    profile.setMaxSize(7500);
    profile.setValidity(validity);
    profile.setNotBeforeTime("current");

    if (certLevel == CertLevel.EndEntity) {
      profile.setKeypairGeneration(BuilderUtil.createKeypairGenControl(
          KeypairGenMode.INHERITCA, null));
    }

    // SignatureAlgorithms
    List<SignSpec> algos = Arrays.asList(
        SignSpec.RSA_SHA256,
        SignSpec.RSA_SHA384,
        SignSpec.RSA_SHA512,
        SignSpec.ECDSA_SHA256,
        SignSpec.ECDSA_SHA384,
        SignSpec.ECDSA_SHA512,
        SignSpec.RSAPSS_SHA256,
        SignSpec.RSAPSS_SHA384,
        SignSpec.RSAPSS_SHA512);
    profile.setSignatureAlgorithms(algos);

    // Subject
    profile.setSubject(new ArrayList<>());

    // Key
    profile.setKeyAlgorithms(BuilderUtil.createKeyAlgorithmTypes(
        AllowKeyMode.RSA, AllowKeyMode.EC_SECP));

    return profile;
  } // method getBaseCabProfile

  protected static XijsonCertprofileType getBaseProfile(
      String description, CertLevel certLevel, String validity,
      KeypairGenMode keypairGenMode, AllowKeyMode... allowedKeyMode) {
    return getBaseProfile(description, certLevel, validity,
        false, keypairGenMode, allowedKeyMode);
  }

  protected static XijsonCertprofileType getBaseProfile(
      String description, CertLevel certLevel, String validity,
      boolean useMidnightNotBefore,
      KeypairGenMode keypairGenMode,
      AllowKeyMode... allowedKeyModes) {
    XijsonCertprofileType profile = new XijsonCertprofileType();

    profile.setMetadata(createDescription(description));

    profile.setCertLevel(certLevel);
    profile.setMaxSize(7500);
    profile.setValidity(validity);
    profile.setNotBeforeTime(useMidnightNotBefore ? "midnight" : "current");

    if (certLevel == CertLevel.EndEntity) {
      profile.setKeypairGeneration(BuilderUtil.createKeypairGenControl(
          keypairGenMode,
          allowedKeyModes == null || allowedKeyModes.length == 0
              ? AllowKeyMode.RSA : allowedKeyModes[0]));
    }

    // SignatureAlgorithms
    List<SignSpec> algos = Arrays.asList(
        SignSpec.RSA_SHA256,
        SignSpec.RSA_SHA384,
        SignSpec.RSA_SHA512,
        SignSpec.ECDSA_SHA256,
        SignSpec.ECDSA_SHA384,
        SignSpec.ECDSA_SHA512,
        SignSpec.RSAPSS_SHA256,
        SignSpec.RSAPSS_SHA384,
        SignSpec.RSAPSS_SHA512,
        SignSpec.ECDSA_SHAKE128,
        SignSpec.ECDSA_SHAKE256,
        SignSpec.RSAPSS_SHAKE128,
        SignSpec.RSAPSS_SHAKE256,
        SignSpec.ED25519,
        SignSpec.ED448,
        SignSpec.SM2_SM3);

    profile.setSignatureAlgorithms(algos);

    // Subject
    profile.setSubject(new ArrayList<>());

    // Key
    profile.setKeyAlgorithms(
        BuilderUtil.createKeyAlgorithmTypes(allowedKeyModes));

    return profile;
  } // method getBaseProfile

  protected static XijsonCertprofileType
      getEeBaseProfileForEdwardsOrMontgomeryCurves(
          String description, String validity,
          boolean edwards, boolean curve25519) {
    XijsonCertprofileType profile = new XijsonCertprofileType();

    profile.setMetadata(createDescription(description));

    profile.setCertLevel(CertLevel.EndEntity);
    profile.setMaxSize(7500);
    profile.setValidity(validity);
    profile.setNotBeforeTime("current");

    AllowKeyMode allowKeyMode;
    if (edwards) {
      allowKeyMode = curve25519 ? AllowKeyMode.ED25519 : AllowKeyMode.ED448;
    } else {
      allowKeyMode = curve25519 ? AllowKeyMode.X25519 : AllowKeyMode.X448;
    }

    profile.setKeypairGeneration(BuilderUtil.createKeypairGenControl(
        KeypairGenMode.FIRST_ALLOWED_KEY, allowKeyMode));

    // SignatureAlgorithm
    List<SignSpec> algos = Arrays.asList(
        SignSpec.ED25519,
        SignSpec.ED448);

    profile.setSignatureAlgorithms(algos);

    // Subject
    profile.setSubject(new ArrayList<>());

    // public key
    profile.setKeyAlgorithms(BuilderUtil.createKeyAlgorithmTypes(allowKeyMode));

    // KeyUsage
    KeyUsage[] usages = edwards
        ? new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.contentCommitment}
        : new KeyUsage[]{KeyUsage.keyAgreement};

    List<ExtensionType> extensions = profile.getExtensions();
    extensions.add(createExtension(ExtensionID.keyUsage, true, true));
    last(extensions).setKeyUsage(createKeyUsage(usages, null));

    return profile;
  } // method getEeBaseProfileForEdwardsOrMontgomeryCurves

  protected static <T> T last(List<T> list) {
    if (list == null || list.isEmpty()) {
      return null;
    } else {
      return list.get(list.size() - 1);
    }

  } // method last

  protected static void addRdns(
      XijsonCertprofileType profile, RdnType... rdns) {
    List<RdnType> list = profile.getSubject();
    Collections.addAll(list, rdns);
  }

}
