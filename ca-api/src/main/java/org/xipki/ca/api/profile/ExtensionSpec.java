// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.api.profile.Certprofile.CertDomain;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;

import java.util.*;

/**
 * Extension specification.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class ExtensionSpec {

  private static final Set<String> specialUseDomains = new HashSet<>(Arrays.asList(
      ".in-addr.arpa", // [RFC6761]
      ".ip6.arpa",     // [RFC6762]
      "home.arpa",     // [RFC8375]
      "example",       // [RFC6761]
      "example.com",   // [RFC6761]
      "example.net",   // [RFC6761]
      "example.org",   // [RFC6761]
      "invalid",       // [RFC6761]
      "local",         // [RFC6762]
      "localhost",     // [RFC6761]
      "onion",         // [RFC7686]
      "test"           // [RFC6761]
      ));

  private static final Map<CertLevel, ExtensionSpec> rfc5280Instances = new HashMap<>();

  private static final Map<CertLevel, ExtensionSpec> browserForumInstances = new HashMap<>();

  static {
    rfc5280Instances.put(CertLevel.RootCA, new Rfc5280RootCA());
    rfc5280Instances.put(CertLevel.SubCA, new Rfc5280SubCA());
    rfc5280Instances.put(CertLevel.CROSS, new Rfc5280SubCA());
    rfc5280Instances.put(CertLevel.EndEntity, new Rfc5280EndEntity());

    browserForumInstances.put(CertLevel.RootCA, new BrowserForumBRRootCA());
    browserForumInstances.put(CertLevel.SubCA, new BrowserForumBRSubCA());
    browserForumInstances.put(CertLevel.CROSS, new BrowserForumBRSubCA());
    browserForumInstances.put(CertLevel.EndEntity, new BrowserForumBREndEntity());
  }

  public abstract Set<ASN1ObjectIdentifier> getRequiredExtensions();

  public abstract boolean isNotPermitted(ASN1ObjectIdentifier type);

  public abstract boolean isCriticalOnly(ASN1ObjectIdentifier type);

  public abstract boolean isNonCriticalOnly(ASN1ObjectIdentifier type);

  public abstract boolean isNonRequest(ASN1ObjectIdentifier type);

  public static boolean isValidPublicDomain(String domain) {
    if (!DomainValidator.getInstance().isValid(domain)) {
      return false;
    }

    String loDomain = domain.toLowerCase();
    for (String m : specialUseDomains) {
      if (loDomain.endsWith(m)) {
        return false;
      }
    }

    return true;
  } // method isValidPublicDomain

  public static boolean isValidPublicIPv4Address(byte[] ipv4Address) {
    if (ipv4Address == null || ipv4Address.length != 4) {
      return false;
    }

    int byte0 = 0xFF & ipv4Address[0];
    int byte1 = 0xFF & ipv4Address[1];

    if (byte0 == 10) {
      return false;
    } else if (byte0 == 172) {
      return !(byte1 >= 16 && byte1 <= 31);
    } else if (byte0 == 192) {
      return byte1 != 168;
    } else {
      return true;
    }
  } // method isValidPublicIPv4Address

  public static ExtensionSpec getExtensionSpec(CertDomain domain, CertLevel certLevel) {
    return domain == CertDomain.CABForumBR ? browserForumInstances.get(certLevel) : rfc5280Instances.get(certLevel);
  } // method getExtensionSpec

  private static class Rfc5280 extends ExtensionSpec {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS = Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
          Extension.keyUsage,
          Extension.policyMappings,
          Extension.nameConstraints,
          Extension.policyConstraints,
          Extension.inhibitAnyPolicy,
          ObjectIdentifiers.Extn.id_pe_tlsfeature)));

    private static final Set<ASN1ObjectIdentifier> NON_CRITICAL_ONLY_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.authorityKeyIdentifier,
            Extension.subjectKeyIdentifier,
            Extension.issuerAlternativeName,
            Extension.subjectDirectoryAttributes,
            Extension.freshestCRL,
            Extension.authorityInfoAccess,
            Extension.subjectInfoAccess,
            Extn.id_SCTs,
            Extn.id_GMT_0015_ICRegistrationNumber,
            Extn.id_GMT_0015_IdentityCode,
            Extn.id_GMT_0015_InsuranceNumber,
            Extn.id_GMT_0015_OrganizationCode,
            Extn.id_GMT_0015_TaxationNumber)));

    private static final Set<ASN1ObjectIdentifier> NON_REQUEST_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.authorityKeyIdentifier,
            Extension.issuerAlternativeName,
            Extension.cRLDistributionPoints,
            Extension.freshestCRL,
            Extn.id_SCTs,
            Extension.inhibitAnyPolicy)));

    public Set<ASN1ObjectIdentifier> getRequiredExtensions() {
      return REQUIRED_EXTENSIONS;
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type);
    }

    @Override
    public boolean isNonRequest(ASN1ObjectIdentifier type) {
      return NON_REQUEST_EXTENSIONS.contains(type);
    }

    @Override
    public boolean isNotPermitted(ASN1ObjectIdentifier type) {
      return false;
    }

  } // class Rfc5280

  private static class Rfc5280RootCA extends Rfc5280 {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.basicConstraints,
            Extension.subjectKeyIdentifier,
            Extension.keyUsage
            )));

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.certificatePolicies,
            Extension.extendedKeyUsage,
            // not required in RFC5280, forbidden by several national standards,
            // e.g. chinese GM/T 0015 and German Gematik.
            Extension.authorityKeyIdentifier)));

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.basicConstraints,
            Extension.keyUsage)));

    private static final Set<ASN1ObjectIdentifier> NON_CRITICAL_ONLY_EXTENSIONS = Collections.emptySet();

    private final Set<ASN1ObjectIdentifier> requiredExtensions;

    private Rfc5280RootCA() {
      Set<ASN1ObjectIdentifier> set = new HashSet<>();
      set.addAll(REQUIRED_EXTENSIONS);
      set.addAll(super.getRequiredExtensions());
      this.requiredExtensions = Collections.unmodifiableSet(set);
    }

    @Override
    public Set<ASN1ObjectIdentifier> getRequiredExtensions() {
      return requiredExtensions;
    }

    @Override
    public boolean isNotPermitted(ASN1ObjectIdentifier type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class Rfc5280RootCA

  private static class Rfc5280SubCA extends Rfc5280 {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.basicConstraints,
            Extension.subjectKeyIdentifier,
            Extension.keyUsage)));

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS = Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.basicConstraints, // BR
            Extension.keyUsage, // BR
            Extension.nameConstraints))); // BR

    private static final Set<ASN1ObjectIdentifier> NON_CRITICAL_ONLY_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.certificatePolicies, // BR
            Extension.cRLDistributionPoints, // BR
            Extension.authorityInfoAccess, // BR
            Extension.extendedKeyUsage))); // BR

    private final Set<ASN1ObjectIdentifier> requiredExtensions;

    private Rfc5280SubCA() {
      Set<ASN1ObjectIdentifier> set = new HashSet<>();
      set.addAll(REQUIRED_EXTENSIONS);
      set.addAll(super.getRequiredExtensions());
      this.requiredExtensions = Collections.unmodifiableSet(set);
    }

    @Override
    public Set<ASN1ObjectIdentifier> getRequiredExtensions() {
      return requiredExtensions;
    }

    @Override
    public boolean isNotPermitted(ASN1ObjectIdentifier type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class Rfc5280SubCA

  private static class Rfc5280EndEntity extends Rfc5280 {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Collections.singletonList(
                Extension.subjectKeyIdentifier)));

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.policyMappings,
            Extension.nameConstraints,
            Extension.policyConstraints,
            Extension.inhibitAnyPolicy)));

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS = Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> NON_CRITICAL_ONLY_EXTENSIONS = Collections.emptySet();

    @Override
    public Set<ASN1ObjectIdentifier> getRequiredExtensions() {
      return REQUIRED_EXTENSIONS;
    }

    @Override
    public boolean isNotPermitted(ASN1ObjectIdentifier type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class Rfc5280EndEntity

  private static class BrowserForumBRRootCA extends Rfc5280RootCA {

  } // class BrowserForumBRRootCA

  private static class BrowserForumBRSubCA extends Rfc5280SubCA {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.certificatePolicies, // BR
            Extension.cRLDistributionPoints, // BR
            Extension.authorityInfoAccess, // BR
            Extension.basicConstraints, // BR
            Extension.keyUsage))); // BR

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS =
        Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.basicConstraints, // BR
            Extension.keyUsage, // BR
            Extension.nameConstraints))); // BR

    private static final Set<ASN1ObjectIdentifier> NON_CRITICAL_ONLY_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.certificatePolicies, // BR
            Extension.cRLDistributionPoints, // BR
            Extension.authorityInfoAccess, // BR
            Extension.extendedKeyUsage))); // BR

    private final Set<ASN1ObjectIdentifier> requiredExtensions;

    private BrowserForumBRSubCA() {
      Set<ASN1ObjectIdentifier> set = new HashSet<>();
      set.addAll(REQUIRED_EXTENSIONS);
      set.addAll(super.getRequiredExtensions());
      this.requiredExtensions = Collections.unmodifiableSet(set);
    }

    @Override
    public Set<ASN1ObjectIdentifier> getRequiredExtensions() {
      return requiredExtensions;
    }

    @Override
    public boolean isNotPermitted(ASN1ObjectIdentifier type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class BrowserForumBRSubCA

  private static class BrowserForumBREndEntity extends Rfc5280EndEntity {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.certificatePolicies, // BR
            Extension.authorityInfoAccess, // BR
            Extension.extendedKeyUsage, // BR
            Extension.subjectAlternativeName))); // BR

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS =
        Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> NON_CRITICAL_ONLY_EXTENSIONS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            Extension.certificatePolicies, // BR
            Extension.cRLDistributionPoints, // BR
            Extension.authorityInfoAccess))); // BR

    private final Set<ASN1ObjectIdentifier> requiredExtensions;

    private BrowserForumBREndEntity() {
      Set<ASN1ObjectIdentifier> set = new HashSet<>();
      set.addAll(REQUIRED_EXTENSIONS);
      set.addAll(super.getRequiredExtensions());
      this.requiredExtensions = Collections.unmodifiableSet(set);
    }

    @Override
    public Set<ASN1ObjectIdentifier> getRequiredExtensions() {
      return requiredExtensions;
    }

    @Override
    public boolean isNotPermitted(ASN1ObjectIdentifier type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class BrowserForumBREndEntity

}
