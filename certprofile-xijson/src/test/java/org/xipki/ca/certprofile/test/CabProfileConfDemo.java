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
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.X509ProfileType;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers.BaseRequirements;
import org.xipki.security.ObjectIdentifiers.DN;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Demo the creation of xijson configuration for CA/Browser Forum certificates.
 *
 * @author Lijun Liao
 */

public class CabProfileConfDemo extends ProfileConfBuilder {

  public static void main(String[] args) {
    try {
      // CA/Browser Forum
      certprofileCabRootCa("certprofile-cab-rootca.json");
      certprofileCabSubCa("certprofile-cab-subca.json");
      certprofileCabDomainValidatedTls("certprofile-cab-domain-validated.json");
      certprofileCabOrganizationValidatedTls("certprofile-cab-org-validated.json");
      certprofileCabIndividualValidatedTls("certprofile-cab-individual-validated.json");
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void certprofileCabRootCa(String destFilename) {
    X509ProfileType profile = getBaseCabProfile("certprofile RootCA (CA/Browser Forum BR)",
        CertLevel.RootCA, "10y");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign}, null));

    marshall(profile, destFilename, true);
  } // method certprofileCabRootCa

  private static void certprofileCabSubCa(String destFilename) {
    X509ProfileType profile = getBaseCabProfile("certprofile SubCA (CA/Browser Forum BR)",
        CertLevel.SubCA, "8y");

    // Subject
    addRdns(profile, rdn(DN.C), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - controls
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    list.add(createExtension(Extension.cRLDistributionPoints, true, false));
    last(list).setCrlDistributionPoints(createCrlDistibutoionPoints());

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

    // Extensions - CertificatePolicies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    Map<ASN1ObjectIdentifier, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(new ASN1ObjectIdentifier("1.2.3.4"), "http://abc.def.de/cfp");
    last(list).setCertificatePolicies(createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabSubCa

  private static void certprofileCabDomainValidatedTls(String destFilename) {
    X509ProfileType profile = getBaseCabSubscriberProfile("certprofile TLS (CA/Browser Forum BR, Domain Validated)");

    // Subject
    addRdns(profile, rdn(DN.C), rdn01(DN.OU), rdn01(DN.SN), rdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    List<ExtensionType> list = profile.getExtensions();
    // Extensions - CertificatePolicies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    Map<ASN1ObjectIdentifier, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(BaseRequirements.id_domain_validated, null);
    last(list).setCertificatePolicies(createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabDomainValidatedTls

  private static void certprofileCabOrganizationValidatedTls(String destFilename) {
    X509ProfileType profile = getBaseCabSubscriberProfile(
        "certprofile TLS (CA/Browser Forum BR, Organization Validated)");

    // Subject
    addRdns(profile, rdn(DN.C), rdn01(DN.ST), rdn01(DN.localityName), rdn(DN.O), rdn01(DN.OU), rdn01(DN.SN),
        rdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    List<ExtensionType> list = profile.getExtensions();
    // Extensions - CertificatePolicies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    Map<ASN1ObjectIdentifier, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(BaseRequirements.id_organization_validated, null);
    last(list).setCertificatePolicies(createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabOrganizationValidatedTls

  private static void certprofileCabIndividualValidatedTls(String destFilename) {
    X509ProfileType profile = getBaseCabSubscriberProfile(
        "certprofile TLS (CA/Browser Forum BR, Individual Validated)");

    // Subject
    addRdns(profile, rdn(DN.C), rdn01(DN.ST), rdn01(DN.localityName), rdn(DN.givenName),
        rdn(DN.surname), rdn01(DN.SN), rdn(DN.CN, 1, 1, REGEX_FQDN, null, null));

    List<ExtensionType> list = profile.getExtensions();
    // Extensions - CertificatePolicies
    list.add(createExtension(Extension.certificatePolicies, true, false));
    Map<ASN1ObjectIdentifier, String> policiesIdAndCpsMap = new HashMap<>();
    policiesIdAndCpsMap.put(BaseRequirements.id_individual_validated, null);
    last(list).setCertificatePolicies(createCertificatePolicies(policiesIdAndCpsMap));

    marshall(profile, destFilename, true);
  } // method certprofileCabOrganizationValidatedTls
}
