// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.ca.api.profile.id.ExtendedKeyUsageID;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.ca.certprofile.xijson.conf.RdnType;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.security.pkix.KeyUsage;
import org.xipki.util.codec.TripleState;

import java.util.Arrays;
import java.util.List;

/**
 * Demo the creation of json configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class ProfileConfDemo extends ProfileConfBuilder {

  public static void main(String[] args) {
    try {
      certprofileCross(qa_dir + "/certprofile-cross.json");
      certprofileRootCa(mgmt_dir + "/certprofile-rootca.json",
          qa_dir + "/certprofile-rootca.json");
      certprofileSubCa (mgmt_dir + "/certprofile-subca.json",
          qa_dir + "/certprofile-subca.json");
      certprofileOcsp  (mgmt_dir + "/certprofile-ocsp.json",
          qa_dir + "/certprofile-ocsp.json");
      certprofileScep  (mgmt_dir + "/certprofile-scep.json",
          qa_dir + "/certprofile-scep.json");
      certprofileSmime (false, mgmt_dir + "/certprofile-smime.json",
          qa_dir + "/certprofile-smime.json");
      certprofileSmime (true, qa_dir + "/certprofile-smime-legacy.json");
      certprofileTls(
          new String[]{mgmt_dir + "/certprofile-tls.json",
              qa_dir + "/certprofile-tls.json"},
          KeyUsageMode.DEFAULT, KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.ALL);

      certprofileTlsC(mgmt_dir + "/certprofile-tls-c.json",
          qa_dir + "/certprofile-tls-c.json");

      certprofileMaxTime(qa_dir + "/certprofile-max-time.json");

      certprofileTls(qa_dir + "/certprofile-tls-rsa.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.RSA);

      certprofileTls(qa_dir + "/certprofile-tls-ec.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.EC);

      certprofileTls(qa_dir + "/certprofile-tls-ed25519.json",
          KeyUsageMode.SIGN_ONLY,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.ED25519);

      certprofileTls(qa_dir + "/certprofile-tls-mldsa.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.MLDSA);

      certprofileTls(qa_dir + "/certprofile-tls-mlkem.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.MLKEM);

      certprofileTls(qa_dir + "/certprofile-tls-edwards.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.EDDSA);

      certprofileTls(qa_dir + "/certprofile-tls-montgomery.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.XDH);

      certprofileTls(qa_dir + "/certprofile-tls-compsig.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.COMPSIG);

      certprofileTls(qa_dir + "/certprofile-tls-compkem.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.COMPKEM);

      certprofileTls(qa_dir + "/certprofile-tls-enc.json",
          KeyUsageMode.ENC_ONLY,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.ALL_ENC);

      certprofileTls(
          new String[]{mgmt_dir + "/certprofile-tls-sm2.json",
              qa_dir + "/certprofile-tls-sm2.json"},
          KeyUsageMode.SIGN_ONLY,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.SM2);

      certprofileTls(
          new String[]{mgmt_dir + "/certprofile-tls-sm2-enc.json",
              qa_dir + "/certprofile-tls-sm2-enc.json"},
          KeyUsageMode.ENC_ONLY,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.SM2);

      certprofileTlsEdwardsOrMontgomery(qa_dir + "/certprofile-ed25519.json",
          true, true);
      certprofileTlsEdwardsOrMontgomery(qa_dir + "/certprofile-ed448.json",
          true, false);
      certprofileTlsEdwardsOrMontgomery(qa_dir + "/certprofile-x25519.json",
          false, true);
      certprofileTlsEdwardsOrMontgomery(qa_dir + "/certprofile-x448.json",
          false, false);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void certprofileRootCa(String... destFilenames) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile rootca", CertLevel.RootCA, "10y",
        KeypairGenMode.FORBIDDEM, AllowKeyMode.ALL_SIGN);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn  (AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.extensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign},  null,
        profile.keyAlgorithms()));

    for (String destFilename : destFilenames) {
      marshall(profile, destFilename, true);
    }
  } // method certprofileRootCa

  private static void certprofileCross(String... destFilenames) {
    XijsonCertprofileType profile = getBaseProfile("certprofile cross",
        CertLevel.CROSS, "10y", KeypairGenMode.FORBIDDEM,
        AllowKeyMode.ALL_SIGN);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.extensions();
    ExtensionType extensionType = createExtension(
        ExtensionID.subjectKeyIdentifier, true, false);
    extensionType.setInRequest(TripleState.optional);
    list.add(extensionType);
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - basicConstraints
    extensionType = createExtension(ExtensionID.basicConstraints, true, true);
    extensionType.setInRequest(TripleState.optional);
    list.add(extensionType);

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign}, null,
        profile.keyAlgorithms()));

    for (String destFilename : destFilenames) {
      marshall(profile, destFilename, true);
    }
  } // method certprofileCross

  private static void certprofileSubCa(String... destFilenames) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile subca", CertLevel.SubCA, "8y",
        KeypairGenMode.FORBIDDEM, AllowKeyMode.ALL_SIGN);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn  (AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.extensions();

    // Extensions - controls
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));
    last(list).setBasicConstraints(createBasicConstraints(1));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign}, null,
        profile.keyAlgorithms()));

    for (String destFilename : destFilenames) {
      marshall(profile, destFilename, true);
    }
  } // method certprofileSubCa

  private static void certprofileOcsp(String... destFilenames) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile ocsp", CertLevel.EndEntity, "5y",
        KeypairGenMode.INHERITCA, AllowKeyMode.ALL_SIGN);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.organizationIdentifier),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.extensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));
    list.add(createExtension(ExtensionID.ocspNoCheck, true, false));

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
        new KeyUsage[]{KeyUsage.contentCommitment}, null,
        profile.keyAlgorithms()));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.OCSPSigning}, null));

    for (String destFilename : destFilenames) {
      marshall(profile, destFilename, true);
    }
  } // method certprofileOcsp

  private static void certprofileScep(String... destFilenames) {
    XijsonCertprofileType profile = getBaseProfile("certprofile scep",
        CertLevel.EndEntity, "5y",
        KeypairGenMode.FIRST_ALLOWED_KEY, AllowKeyMode.RSA);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.extensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.keyEncipherment},
        null, profile.keyAlgorithms()));

    for (String destFilename : destFilenames) {
      marshall(profile, destFilename, true);
    }
  } // method certprofileScep

  private static void certprofileSmime(
      boolean legacy, String... destFilenames) {
    String desc = legacy ? "certprofile s/mime legacy" : "certprofile s/mime";
    XijsonCertprofileType profile = getBaseProfile(desc, CertLevel.EndEntity,
        "5y", KeypairGenMode.INHERITCA, AllowKeyMode.ALL);

    // Subject
    addRdns(profile,
        rdn(AttributeType.C),
        rdn(AttributeType.O),
        rdn01(AttributeType.OU));

    RdnType emailRdn = rdn(AttributeType.emailAddress, legacy ? 1 : 0,
        legacy ? 1 : 0, null, null, GeneralNameTag.rfc822Name);
    addRdns(profile, emailRdn);

    addRdns(profile,
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.extensions();
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - SubjectAltNames
    list.add(createExtension(ExtensionID.subjectAlternativeName, true, false));
    last(list).setInRequest(TripleState.optional);
    GeneralNameType san = new GeneralNameType(
        List.of(GeneralNameTag.rfc822Name));
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
            KeyUsage.keyEncipherment, KeyUsage.keyAgreement},
        null, profile.keyAlgorithms()));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.emailProtection}, null));

    // Extensions - SMIMECapabilities
    list.add(createExtension(ExtensionID.smimeCapabilities, true, false));
    last(list).setSmimeCapabilities(createSmimeCapabilities());

    for (String destFilename : destFilenames) {
      marshall(profile, destFilename, true);
    }
  } // method certprofileSmime

  private static void certprofileTlsEdwardsOrMontgomery(
      String destFilename, boolean edwards, boolean curve25519) {
    String desc = "certprofile tls with " +
        (edwards ? "edwards " : "montmomery ") +
        (curve25519 ? "25519" : "448") + " curves";

    XijsonCertprofileType profile =
        getEeBaseProfileForEdwardsOrMontgomeryCurves(
            desc, "2y", edwards, curve25519);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN, 1, 1, REGEX_FQDN, null,
              GeneralNameTag.DNSName));

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.extensions();
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - SubjectAltNames
    list.add(createExtension(ExtensionID.subjectAlternativeName, true, false));
    last(list).setInRequest(TripleState.optional);
    GeneralNameType san = new GeneralNameType(Arrays.asList(
        GeneralNameTag.DNSName, GeneralNameTag.IPAddress));
    last(list).setSubjectAltName(san);

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.serverAuth,
            ExtendedKeyUsageID.clientAuth},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileTlsEdwardsOrMontgomery

  private static void certprofileTls(
      String destFilename, KeyUsageMode keyUsageMode,
      KeypairGenMode keypairGenMode, AllowKeyMode... modes) {
    certprofileTls(new String[]{destFilename}, keyUsageMode,
        keypairGenMode, modes);
  }

  private static void certprofileTls(
      String[] destFilenames, KeyUsageMode keyUsageMode,
      KeypairGenMode keypairGenMode, AllowKeyMode... modes) {
    String desc = "certprofile tls";
    if (keyUsageMode == KeyUsageMode.SIGN_ONLY) {
      desc += " sign";
    } else if (keyUsageMode == KeyUsageMode.ENC_ONLY) {
      desc += " enc";
    }

    XijsonCertprofileType profile = getBaseProfile(desc, CertLevel.EndEntity,
        "5y", keypairGenMode, modes);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN, 1, 1, REGEX_FQDN, null,
              GeneralNameTag.DNSName));

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.extensions();
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - SubjectAltNames
    list.add(createExtension(ExtensionID.subjectAlternativeName, true, false));
    last(list).setInRequest(TripleState.optional);
    GeneralNameType san = new GeneralNameType(Arrays.asList(
        GeneralNameTag.DNSName, GeneralNameTag.IPAddress));
    last(list).setSubjectAltName(san);

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(ExtensionID.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(ExtensionID.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    KeyUsage[] usages;
    if (keyUsageMode == KeyUsageMode.ENC_ONLY) {
      usages = new KeyUsage[] {KeyUsage.dataEncipherment,
          KeyUsage.keyEncipherment};
    } else if (keyUsageMode == KeyUsageMode.SIGN_ONLY) {
      usages = new KeyUsage[] {KeyUsage.digitalSignature};
    } else {
      usages = new KeyUsage[] {KeyUsage.digitalSignature,
          KeyUsage.dataEncipherment, KeyUsage.keyEncipherment,
          KeyUsage.keyAgreement};
    }

    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(usages, null,
        profile.keyAlgorithms()));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.serverAuth},
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.clientAuth}));

    for (String destFilename : destFilenames) {
      marshall(profile, destFilename, true);
    }
  } // method certprofileTls

  private static void certprofileTlsC(String... destFilenames) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile tls-c", CertLevel.EndEntity, "5y",
        KeypairGenMode.FIRST_ALLOWED_KEY, AllowKeyMode.ALL);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.extensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

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
            KeyUsage.keyEncipherment, KeyUsage.keyAgreement},
        null, profile.keyAlgorithms()));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.clientAuth}, null));

    for (String destFilename : destFilenames) {
      marshall(profile, destFilename, true);
    }
  } // method certprofileTlsC

  private static void certprofileMaxTime(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile max-time", CertLevel.EndEntity,
        "UNDEFINED", KeypairGenMode.INHERITCA, AllowKeyMode.ALL);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN, 1, 1, ":FQDN", null));

    // Extensions
    List<ExtensionType> list = profile.extensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

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
            KeyUsage.keyEncipherment, KeyUsage.keyAgreement},
        null, profile.keyAlgorithms()));

    marshall(profile, destFilename, true);
  } // method certprofileMaxTime

}
