// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.OIDs;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Extension specification.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class ExtensionSpec {

  private static final Set<String> specialUseDomains =
      new HashSet<>(Arrays.asList(
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

  private static final Map<CertLevel, ExtensionSpec> rfc5280Instances =
      new HashMap<>();

  private static final Map<CertLevel, ExtensionSpec> browserForumInstances =
      new HashMap<>();

  private static final AtomicBoolean instancesInitialized =
      new AtomicBoolean(false);

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

  public static ExtensionSpec getExtensionSpec(
      CertDomain domain, CertLevel certLevel) {
    if (!instancesInitialized.get()) {
      synchronized (instancesInitialized) {
        rfc5280Instances.put(CertLevel.RootCA, new Rfc5280RootCA());
        Rfc5280SubCA subCA = new Rfc5280SubCA();
        rfc5280Instances.put(CertLevel.SubCA, subCA);
        rfc5280Instances.put(CertLevel.CROSS, subCA);
        rfc5280Instances.put(CertLevel.EndEntity, new Rfc5280EndEntity());

        browserForumInstances.put(CertLevel.RootCA, new BrowserForumBRRootCA());
        BrowserForumBRSubCA brSubCA = new BrowserForumBRSubCA();
        browserForumInstances.put(CertLevel.SubCA, brSubCA);
        browserForumInstances.put(CertLevel.CROSS, brSubCA);
        browserForumInstances.put(CertLevel.EndEntity,
            new BrowserForumBREndEntity());

        instancesInitialized.set(true);
      }
    }

    return domain == CertDomain.CABForumBR
        ? browserForumInstances.get(certLevel)
        : rfc5280Instances.get(certLevel);
  } // method getExtensionSpec

  private static class Rfc5280 extends ExtensionSpec {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Set.of(
            OIDs.Extn.keyUsage,
            OIDs.Extn.policyMappings,
            OIDs.Extn.nameConstraints,
            OIDs.Extn.policyConstraints,
            OIDs.Extn.inhibitAnyPolicy);

    private static final Set<ASN1ObjectIdentifier>
        NON_CRITICAL_ONLY_EXTENSIONS = Set.of(
            OIDs.Extn.authorityKeyIdentifier,
            OIDs.Extn.subjectKeyIdentifier,
            OIDs.Extn.issuerAlternativeName,
            OIDs.Extn.subjectDirectoryAttributes,
            OIDs.Extn.freshestCRL,
            OIDs.Extn.authorityInfoAccess,
            OIDs.Extn.subjectInfoAccess,
            OIDs.Extn.id_pe_tlsfeature,
            OIDs.Extn.id_SignedCertificateTimestampList);

    private static final Set<ASN1ObjectIdentifier> NON_REQUEST_EXTENSIONS =
        Set.of(
            OIDs.Extn.authorityKeyIdentifier,
            OIDs.Extn.issuerAlternativeName,
            OIDs.Extn.cRLDistributionPoints,
            OIDs.Extn.authorityInfoAccess,
            OIDs.Extn.freshestCRL,
            OIDs.Extn.id_SignedCertificateTimestampList,
            OIDs.Extn.inhibitAnyPolicy,
            OIDs.Extn.id_pkix_ocsp_nocheck);

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
        Set.of(
            OIDs.Extn.basicConstraints,
            OIDs.Extn.subjectKeyIdentifier,
            OIDs.Extn.keyUsage);

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS =
        Set.of(
            OIDs.Extn.certificatePolicies,
            OIDs.Extn.extendedKeyUsage,
            // not required in RFC5280, forbidden by several national standards,
            // e.g. chinese GM/T 0015 and German Gematik.
            OIDs.Extn.authorityKeyIdentifier);

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Set.of(
            OIDs.Extn.basicConstraints,
            OIDs.Extn.keyUsage);

    private static final Set<ASN1ObjectIdentifier> NON_CRITICAL_ONLY_EXTENSIONS
        = Collections.emptySet();

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
      return NON_PERMITTED_EXTENSIONS.contains(type)
          || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isNonCriticalOnly(type);
    }

  } // class Rfc5280RootCA

  private static class Rfc5280SubCA extends Rfc5280 {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Set.of(
            OIDs.Extn.basicConstraints,
            OIDs.Extn.subjectKeyIdentifier,
            OIDs.Extn.keyUsage);

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS
        = Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Set.of(
            OIDs.Extn.basicConstraints, // BR
            OIDs.Extn.keyUsage, // BR
            OIDs.Extn.nameConstraints); // BR

    private static final Set<ASN1ObjectIdentifier>
        NON_CRITICAL_ONLY_EXTENSIONS = Set.of(
            OIDs.Extn.certificatePolicies, // BR
            OIDs.Extn.cRLDistributionPoints, // BR
            OIDs.Extn.authorityInfoAccess, // BR
            OIDs.Extn.extendedKeyUsage); // BR

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
      return NON_PERMITTED_EXTENSIONS.contains(type)
          || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isNonCriticalOnly(type);
    }

  } // class Rfc5280SubCA

  private static class Rfc5280EndEntity extends Rfc5280 {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Set.copyOf(Collections.singletonList(
            OIDs.Extn.subjectKeyIdentifier));

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS =
        Set.of(
            OIDs.Extn.policyMappings,
            OIDs.Extn.nameConstraints,
            OIDs.Extn.policyConstraints);

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS
        = Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> NON_CRITICAL_ONLY_EXTENSIONS
        = Collections.emptySet();

    @Override
    public Set<ASN1ObjectIdentifier> getRequiredExtensions() {
      return REQUIRED_EXTENSIONS;
    }

    @Override
    public boolean isNotPermitted(ASN1ObjectIdentifier type) {
      return NON_PERMITTED_EXTENSIONS.contains(type)
          || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isNonCriticalOnly(type);
    }

  } // class Rfc5280EndEntity

  private static class BrowserForumBRRootCA extends Rfc5280RootCA {

  } // class BrowserForumBRRootCA

  private static class BrowserForumBRSubCA extends Rfc5280SubCA {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Set.of(
            OIDs.Extn.certificatePolicies, // BR
            OIDs.Extn.cRLDistributionPoints, // BR
            OIDs.Extn.authorityInfoAccess, // BR
            OIDs.Extn.basicConstraints, // BR
            OIDs.Extn.keyUsage); // BR

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS =
        Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Set.of(
            OIDs.Extn.basicConstraints, // BR
            OIDs.Extn.keyUsage, // BR
            OIDs.Extn.nameConstraints); // BR

    private static final Set<ASN1ObjectIdentifier>
        NON_CRITICAL_ONLY_EXTENSIONS = Set.of(
            OIDs.Extn.certificatePolicies, // BR
            OIDs.Extn.cRLDistributionPoints, // BR
            OIDs.Extn.authorityInfoAccess, // BR
            OIDs.Extn.extendedKeyUsage); // BR

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
      return NON_PERMITTED_EXTENSIONS.contains(type)
          || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isNonCriticalOnly(type);
    }

  } // class BrowserForumBRSubCA

  private static class BrowserForumBREndEntity extends Rfc5280EndEntity {

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EXTENSIONS =
        Set.of(
            OIDs.Extn.certificatePolicies, // BR
            OIDs.Extn.authorityInfoAccess, // BR
            OIDs.Extn.extendedKeyUsage, // BR
            OIDs.Extn.subjectAlternativeName); // BR

    private static final Set<ASN1ObjectIdentifier> NON_PERMITTED_EXTENSIONS =
        Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSIONS =
        Collections.emptySet();

    private static final Set<ASN1ObjectIdentifier>
        NON_CRITICAL_ONLY_EXTENSIONS = Set.of(
            OIDs.Extn.certificatePolicies, // BR
            OIDs.Extn.cRLDistributionPoints, // BR
            OIDs.Extn.authorityInfoAccess); // BR

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
      return NON_PERMITTED_EXTENSIONS.contains(type)
          || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(ASN1ObjectIdentifier type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(ASN1ObjectIdentifier type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type)
          || super.isNonCriticalOnly(type);
    }

  } // class BrowserForumBREndEntity

}
