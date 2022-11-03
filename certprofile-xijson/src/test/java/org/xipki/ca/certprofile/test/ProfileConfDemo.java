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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.certprofile.xijson.conf.*;
import org.xipki.security.EdECConstants;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.util.TripleState;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Demo the creation of xijson configuration.
 *
 * @author Lijun Liao
 */

public class ProfileConfDemo extends ProfileConfBuilder {

  public static void main(String[] args) {
    try {
      certprofileRootCa("certprofile-rootca.json");
      certprofileCross("certprofile-cross.json");
      certprofileSubCa("certprofile-subca.json");
      certprofileOcsp("certprofile-ocsp.json");
      certprofileScep("certprofile-scep.json");
      certprofileSmime("certprofile-smime.json", false);
      certprofileSmime("certprofile-smime-legacy.json", true);
      certprofileTls("certprofile-tls.json", null, false);
      certprofileTlsC("certprofile-tls-c.json");
      certprofileMaxTime("certprofile-max-time.json");
      certprofileGmt0015("certprofile-gmt0015.json");

      certprofileTls("certprofile-tls-rsa.json", KeypairGenerationType.KeyType.RSA, false);
      certprofileTls("certprofile-tls-dsa.json", KeypairGenerationType.KeyType.DSA, false);
      certprofileTls("certprofile-tls-ec.json", KeypairGenerationType.KeyType.EC, false);
      certprofileTls("certprofile-tls-sm2.json", KeypairGenerationType.KeyType.EC, true);

      certprofileTlsEdwardsOrMontgomery("certprofile-ed25519.json", true,  true);
      certprofileTlsEdwardsOrMontgomery("certprofile-ed448.json",   true,  false);
      certprofileTlsEdwardsOrMontgomery("certprofile-x25519.json",  false, true);
      certprofileTlsEdwardsOrMontgomery("certprofile-x448.json",    false, false);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void certprofileRootCa(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile rootca", CertLevel.RootCA, "10y");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign},  null));

    marshall(profile, destFilename, true);
  } // method certprofileRootCa

  private static void certprofileCross(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile cross", CertLevel.CROSS, "10y");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();
    ExtensionType extensionType = createExtension(Extension.subjectKeyIdentifier, true, false);
    extensionType.setInRequest(TripleState.optional);
    list.add(extensionType);
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

    // Extensions - basicConstraints
    extensionType = createExtension(Extension.basicConstraints, true, true);
    extensionType.setInRequest(TripleState.optional);
    list.add(extensionType);

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign}, null));

    marshall(profile, destFilename, true);
  } // method certprofileCross

  private static void certprofileSubCa(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile subca", CertLevel.SubCA, "8y");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));
    last(list).setBasicConstraints(createBasicConstraints(1));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign}, null));

    marshall(profile, destFilename, true);
  } // method certprofileSubCa

  private static void certprofileOcsp(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile ocsp", CertLevel.EndEntity, "5y", true);

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.organizationIdentifier), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));
    list.add(createExtension(Extn.id_extension_pkix_ocsp_nocheck, false, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - AuthorityInfoAccess
    list.add(createExtension(Extension.authorityInfoAccess, true, false));
    last(list).setAuthorityInfoAccess(createAuthorityInfoAccess());

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.contentCommitment}, null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_ocspSigning}, null));

    marshall(profile, destFilename, true);
  } // method certprofileOcsp

  private static void certprofileScep(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile scep", CertLevel.EndEntity, "5y");

    profile.setKeyAlgorithms(createRSAKeyAlgorithms());

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.keyEncipherment}, null));

    marshall(profile, destFilename, true);
  } // method certprofileScep

  private static void certprofileSmime(String destFilename, boolean legacy) {
    String desc = legacy ? "certprofile s/mime legacy" : "certprofile s/mime";
    X509ProfileType profile = getBaseProfile(desc, CertLevel.EndEntity, "5y", true, false);

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU));
    if (legacy) {
      addRdns(profile, rdn(DN.emailAddress));
    }
    addRdns(profile, rdn01(DN.SN), rdn(DN.CN));

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(DN.emailAddress));
    s2sType.setTarget(GeneralNameTag.rfc822Name);

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

    // Extensions - SubjectAltNames
    list.add(createExtension(Extension.subjectAlternativeName, true, false));
    GeneralNameType san = new GeneralNameType();
    last(list).setSubjectAltName(san);
    san.addTags(GeneralNameTag.rfc822Name);

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment, KeyUsage.keyEncipherment},
        null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_emailProtection}, null));

    // Extensions - SMIMECapabilities
    list.add(createExtension(Extn.id_smimeCapabilities, true, false));
    last(list).setSmimeCapabilities(createSmimeCapabilities());

    marshall(profile, destFilename, true);
  } // method certprofileSmime

  private static void certprofileTlsEdwardsOrMontgomery(String destFilename, boolean edwards,
      boolean curve25519) {
    String desc = "certprofile tls with " + (edwards ? "edwards " : "montmomery ")
                    + (curve25519 ? "25519" : "448") + " curves";

    X509ProfileType profile = getEeBaseProfileForEdwardsOrMontgomeryCurves(desc, "2y", edwards, curve25519);

    // Subject
    addRdns(profile, rdn(DN.C), rdn01(DN.O), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(DN.CN));
    s2sType.setTarget(GeneralNameTag.DNSName);

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth, ObjectIdentifiers.XKU.id_kp_clientAuth},
        null));

    marshall(profile, destFilename, true);
  } // method certprofileTlsEdwardsOrMontgomery

  private static void certprofileTls(
      String destFilename, KeypairGenerationType.KeyType kpgKeyType, boolean sm2) {
    String desc = "certprofile tls";
    X509ProfileType profile = getBaseProfile(desc, CertLevel.EndEntity, "5y", true, false);

    if (kpgKeyType != null) {
      KeypairGenerationType kpg = profile.getKeypairGeneration();
      kpg.setInheritCA(false);
      kpg.setKeyType(kpgKeyType);

      Describable.DescribableOid algo;
      Map<String, String> parameters = new HashMap<>();

      switch (kpgKeyType) {
        case DSA:
          algo = createOidType(X9ObjectIdentifiers.id_dsa, "OID");
          parameters.put("plength", "2048");
          parameters.put("qlength", "256");
          break;
        case RSA:
          algo = createOidType(PKCSObjectIdentifiers.rsaEncryption, "RSA");
          parameters.put("keysize", "2048");
          break;
        case EC:
          algo = createOidType(X9ObjectIdentifiers.id_ecPublicKey, "EC");
          parameters.put("curve", (sm2 ? GMObjectIdentifiers.sm2p256v1 : SECObjectIdentifiers.secp256r1).getId());
          break;
        case ED448:
          algo = createOidType(EdECConstants.id_ED448, "ED448");
          parameters = null;
          break;
        case ED25519:
          algo = createOidType(EdECConstants.id_ED25519, "ED25519");
          break;
        case X448:
          algo = createOidType(EdECConstants.id_X448, "X448");
          break;
        case X25519:
          algo = createOidType(EdECConstants.id_X25519, "X25519");
          break;
        default:
          throw new IllegalStateException("unknown KeyType " + kpgKeyType);
      }

      kpg.setAlgorithm(algo);
      kpg.setParameters(parameters);
    }

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN),
        rdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    // SubjectToSubjectAltName
    SubjectToSubjectAltNameType s2sType = new SubjectToSubjectAltNameType();
    profile.getSubjectToSubjectAltNames().add(s2sType);
    s2sType.setSource(createOidType(DN.CN));
    s2sType.setTarget(GeneralNameTag.DNSName);

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment, KeyUsage.keyEncipherment}, null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_serverAuth},
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}));

    marshall(profile, destFilename, true);
  } // method certprofileTls

  private static void certprofileTlsC(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile tls-c", CertLevel.EndEntity, "5y", false);

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment, KeyUsage.keyEncipherment}, null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}, null));

    marshall(profile, destFilename, true);
  } // method certprofileTlsC

  private static void certprofileMaxTime(String destFilename) {
    X509ProfileType profile = getBaseProfile("certprofile max-time", CertLevel.EndEntity,
        "9999y", false);

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN),
        rdn(DN.CN, 1, 1, ":FQDN", null, null));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment, KeyUsage.keyEncipherment}, null));

    marshall(profile, destFilename, true);
  } // method certprofileMaxTime

  private static void certprofileGmt0015(String destFilename) {
    String desc = "certprofile GMT 0015";
    X509ProfileType profile = getBaseProfile(desc, CertLevel.EndEntity, "5y", false);

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn(DN.CN),
        rdn01(Extn.id_GMT_0015_ICRegistrationNumber), rdn01(Extn.id_GMT_0015_IdentityCode),
        rdn01(Extn.id_GMT_0015_InsuranceNumber),      rdn01(Extn.id_GMT_0015_OrganizationCode),
        rdn01(Extn.id_GMT_0015_TaxationNumber));

    // Extensions
    // Extensions - controls
    List<ExtensionType> list = profile.getExtensions();
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, false, false));
    list.add(createExtension(Extension.freshestCRL, false, false));

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
        new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.dataEncipherment, KeyUsage.keyEncipherment}, null));

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, false));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
        new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_clientAuth}, null));

    // Extension id_GMT_0015_ICRegistrationNumber
    ASN1ObjectIdentifier[] gmtOids = new ASN1ObjectIdentifier[] {
        Extn.id_GMT_0015_ICRegistrationNumber, Extn.id_GMT_0015_IdentityCode,  Extn.id_GMT_0015_InsuranceNumber,
        Extn.id_GMT_0015_OrganizationCode,     Extn.id_GMT_0015_TaxationNumber};
    for (ASN1ObjectIdentifier m : gmtOids) {
      list.add(createExtension(m, true, false));
      last(list).setInRequest(TripleState.required);
    }

    marshall(profile, destFilename, true);
  } // method certprofileGmt0015
}
