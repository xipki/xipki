// Copyright (c) 2013-2025 xipki. All rights reserved.
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
import org.xipki.security.KeyUsage;
import org.xipki.util.extra.type.TripleState;

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
      certprofileRootCa("mgmt-cli/certprofile-rootca.json");
      certprofileSubCa ("mgmt-cli/certprofile-subca.json");
      certprofileOcsp  ("mgmt-cli/certprofile-ocsp.json");
      certprofileScep  ("mgmt-cli/certprofile-scep.json");
      certprofileSmime ("mgmt-cli/certprofile-smime.json", false);
      certprofileSmime ("qa/certprofile-smime-legacy.json", true);

      certprofileTls("mgmt-cli/certprofile-tls.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.EC, AllowKeyMode.RSA, AllowKeyMode.SM2);

      certprofileTlsC("mgmt-cli/certprofile-tls-c.json");

      certprofileMaxTime("qa/certprofile-max-time.json");

      certprofileTls("qa/certprofile-tls-rsa.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.RSA);

      certprofileTls("qa/certprofile-tls-ec.json",
          KeyUsageMode.DEFAULT,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.EC);

      certprofileTls("qa/certprofile-tls-ed25519.json",
          KeyUsageMode.SIGN_ONLY,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.ED25519);

      certprofileTls("qa/certprofile-tls-enc.json",
          KeyUsageMode.ENC_ONLY,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.EC, AllowKeyMode.RSA);

      certprofileTls("mgmt-cli/certprofile-tls-sm2.json",
          KeyUsageMode.SIGN_ONLY,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.SM2);

      certprofileTls("mgmt-cli/certprofile-tls-sm2-enc.json",
          KeyUsageMode.ENC_ONLY,
          KeypairGenMode.FIRST_ALLOWED_KEY,
          AllowKeyMode.SM2);

      certprofileTlsEdwardsOrMontgomery("qa/certprofile-ed25519.json",
          true, true);
      certprofileTlsEdwardsOrMontgomery("qa/certprofile-ed448.json",
          true, false);
      certprofileTlsEdwardsOrMontgomery("qa/certprofile-x25519.json",
          false, true);
      certprofileTlsEdwardsOrMontgomery("qa/certprofile-x448.json",
          false, false);

    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void certprofileRootCa(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile rootca", CertLevel.RootCA, "10y",
        KeypairGenMode.FORBIDDEM, AllowKeyMode.RSA, AllowKeyMode.EC,
        AllowKeyMode.SM2, AllowKeyMode.EDDSA);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));

    // Extensions - basicConstraints
    list.add(createExtension(ExtensionID.basicConstraints, true, true));

    // Extensions - keyUsage
    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
        new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign},  null));

    marshall(profile, destFilename, true);
  } // method certprofileRootCa

  private static void certprofileCross(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile("certprofile cross",
        CertLevel.CROSS, "10y", KeypairGenMode.FORBIDDEM,
        AllowKeyMode.RSA, AllowKeyMode.EC, AllowKeyMode.SM2);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();
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
        new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign}, null));

    marshall(profile, destFilename, true);
  } // method certprofileCross

  private static void certprofileSubCa(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile subca", CertLevel.SubCA, "8y",
        KeypairGenMode.FORBIDDEM, AllowKeyMode.RSA, AllowKeyMode.EC,
        AllowKeyMode.SM2, AllowKeyMode.EDDSA);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

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
        new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign}, null));

    marshall(profile, destFilename, true);
  } // method certprofileSubCa

  private static void certprofileOcsp(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile ocsp", CertLevel.EndEntity, "5y",
        KeypairGenMode.INHERITCA, AllowKeyMode.RSA, AllowKeyMode.EC,
        AllowKeyMode.SM2, AllowKeyMode.EDDSA);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.organizationIdentifier),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));
    list.add(createExtension(ExtensionID.ocspNoCheck, false, false));

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
        new KeyUsage[]{KeyUsage.contentCommitment}, null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.OCSPSigning}, null));

    marshall(profile, destFilename, true);
  } // method certprofileOcsp

  private static void certprofileScep(String destFilename) {
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
    List<ExtensionType> list = profile.getExtensions();

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
        null));

    marshall(profile, destFilename, true);
  } // method certprofileScep

  private static void certprofileSmime(String destFilename, boolean legacy) {
    String desc = legacy ? "certprofile s/mime legacy" : "certprofile s/mime";
    XijsonCertprofileType profile = getBaseProfile(desc, CertLevel.EndEntity,
        "5y", KeypairGenMode.INHERITCA, AllowKeyMode.RSA,
        AllowKeyMode.EC, AllowKeyMode.SM2);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU));
    if (legacy) {
      RdnType emailRdn = rdn(AttributeType.emailAddress, 0, 1, null, null,
          GeneralNameTag.rfc822Name);

      addRdns(profile, emailRdn);
    }
    addRdns(profile,
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - SubjectAltNames
    list.add(createExtension(ExtensionID.subjectAlternativeName, true, false));
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
            KeyUsage.keyEncipherment},
        null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.emailProtection}, null));

    // Extensions - SMIMECapabilities
    list.add(createExtension(ExtensionID.smimeCapabilities, true, false));
    last(list).setSmimeCapabilities(createSmimeCapabilities());

    marshall(profile, destFilename, true);
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
        rdn  (AttributeType.CN, 1, 1, REGEX_FQDN, null));

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - SubjectAltNames
    list.add(createExtension(ExtensionID.subjectAlternativeName, true, false));
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
        rdn  (AttributeType.CN, 1, 1, REGEX_FQDN, null));

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, false, false));
    list.add(createExtension(ExtensionID.freshestCRL, false, false));

    // Extensions - SubjectAltNames
    list.add(createExtension(ExtensionID.subjectAlternativeName, true, false));
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
          KeyUsage.dataEncipherment, KeyUsage.keyEncipherment};
    }

    list.add(createExtension(ExtensionID.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(usages, null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.serverAuth},
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.clientAuth}));

    marshall(profile, destFilename, true);
  } // method certprofileTls

  private static void certprofileTlsC(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile tls-c", CertLevel.EndEntity, "5y",
        KeypairGenMode.FIRST_ALLOWED_KEY, AllowKeyMode.RSA, AllowKeyMode.EC,
        AllowKeyMode.SM2);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

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
            KeyUsage.keyEncipherment},
        null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(ExtensionID.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ExtendedKeyUsageID[]{ExtendedKeyUsageID.clientAuth}, null));

    marshall(profile, destFilename, true);
  } // method certprofileTlsC

  private static void certprofileMaxTime(String destFilename) {
    XijsonCertprofileType profile = getBaseProfile(
        "certprofile max-time", CertLevel.EndEntity,
        "UNDEFINED", KeypairGenMode.INHERITCA, AllowKeyMode.RSA,
        AllowKeyMode.EC, AllowKeyMode.SM2);

    // Subject
    addRdns(profile,
        rdn01(AttributeType.C),
        rdn01(AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN, 1, 1, ":FQDN", null));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

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
            KeyUsage.keyEncipherment},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileMaxTime

}
