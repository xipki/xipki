// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.security.KeyUsage;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Demo the creation of json configuration for CA/Browser Forum certificates.
 *
 * @author Lijun Liao (xipki)
 */

public class CabProfileConfDemo extends ProfileConfBuilder {

  public static void main(String[] args) {
    try {
      // CA/Browser Forum
      certprofileCabRootCa("qa/certprofile-cab-rootca.json");
      certprofileCabSubCa ("qa/certprofile-cab-subca.json");
      certprofileCabDomainValidatedTls      (
          "qa/certprofile-cab-domain-validated.json");
      certprofileCabOrganizationValidatedTls(
          "qa/certprofile-cab-org-validated.json");
      certprofileCabIndividualValidatedTls  (
          "qa/certprofile-cab-individual-validated.json");
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void certprofileCabRootCa(String destFilename) {
    XijsonCertprofileType profile = getBaseCabProfile(
        "certprofile RootCA (CA/Browser Forum BR)",
        CertLevel.RootCA, "10y");

    // Subject
    addRdns(profile,
        rdn  (AttributeType.C),
        rdn  (AttributeType.O),
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
        new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign}, null));

    marshall(profile, destFilename, true);
  } // method certprofileCabRootCa

  private static void certprofileCabSubCa(String destFilename) {
    XijsonCertprofileType profile = getBaseCabProfile(
        "certprofile SubCA (CA/Browser Forum BR)",
        CertLevel.SubCA, "8y");

    // Subject
    addRdns(profile,
        rdn  (AttributeType.C),
        rdn  (AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(ExtensionID.subjectKeyIdentifier, true, false));
    list.add(createExtension(ExtensionID.crlDistributionPoints, true, false));

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

    // Extensions - CertificatePolicies
    list.add(createExtension(ExtensionID.certificatePolicies, true, false));
    Map<CertificatePolicyID, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(CertificatePolicyID.ofOidOrName("1.2.3.4"),
        "http://abc.def.de/cfp");
    last(list).setCertificatePolicies(
        createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabSubCa

  private static void certprofileCabDomainValidatedTls(String destFilename) {
    XijsonCertprofileType profile = getBaseCabSubscriberProfile(
        "certprofile TLS (CA/Browser Forum BR, Domain Validated)");

    // Subject
    addRdns(profile,
        rdn  (AttributeType.C),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN, 1, 1, REGEX_FQDN, null));

    List<ExtensionType> list = profile.getExtensions();
    // Extensions - CertificatePolicies
    list.add(createExtension(ExtensionID.certificatePolicies, true, false));
    Map<CertificatePolicyID, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(CertificatePolicyID.domainValidated, null);
    last(list).setCertificatePolicies(
        createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabDomainValidatedTls

  private static void certprofileCabOrganizationValidatedTls(
      String destFilename) {
    XijsonCertprofileType profile = getBaseCabSubscriberProfile(
        "certprofile TLS (CA/Browser Forum BR, Organization Validated)");

    // Subject
    addRdns(profile,
        rdn  (AttributeType.C),
        rdn01(AttributeType.ST),
        rdn01(AttributeType.locality),
        rdn  (AttributeType.O),
        rdn01(AttributeType.OU),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN, 1, 1, REGEX_FQDN, null));

    List<ExtensionType> list = profile.getExtensions();
    // Extensions - CertificatePolicies
    list.add(createExtension(ExtensionID.certificatePolicies, true, false));
    Map<CertificatePolicyID, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(CertificatePolicyID.organizationValidated, null);
    last(list).setCertificatePolicies(
        createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabOrganizationValidatedTls

  private static void certprofileCabIndividualValidatedTls(
      String destFilename) {
    XijsonCertprofileType profile = getBaseCabSubscriberProfile(
        "certprofile TLS (CA/Browser Forum BR, Individual Validated)");

    // Subject
    addRdns(profile,
        rdn  (AttributeType.C),
        rdn01(AttributeType.ST),
        rdn01(AttributeType.locality),
        rdn  (AttributeType.givenName),
        rdn  (AttributeType.surname),
        rdn01(AttributeType.SN),
        rdn  (AttributeType.CN, 1, 1, REGEX_FQDN, null));

    List<ExtensionType> list = profile.getExtensions();
    // Extensions - CertificatePolicies
    list.add(createExtension(ExtensionID.certificatePolicies, true, false));
    Map<CertificatePolicyID, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(CertificatePolicyID.individualValidated, null);
    last(list).setCertificatePolicies(
        createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabOrganizationValidatedTls
}
