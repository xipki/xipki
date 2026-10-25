// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.ca.api.profile.id.ExtensionID;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Extension Spec.
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

  private static final Map<CertLevel, ExtensionSpec> rfc5280Instances = new HashMap<>();

  private static final Map<CertLevel, ExtensionSpec> browserForumInstances = new HashMap<>();

  private static final AtomicBoolean instancesInitialized = new AtomicBoolean(false);

  public abstract Set<Asn1Oid> requiredExtensions();

  public abstract boolean isNotPermitted(Asn1Oid type);

  public abstract boolean isCriticalOnly(Asn1Oid type);

  public abstract boolean isNonCriticalOnly(Asn1Oid type);

  public abstract boolean isNonRequest(Asn1Oid type);

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
        browserForumInstances.put(CertLevel.EndEntity, new BrowserForumBREndEntity());

        instancesInitialized.set(true);
      }
    }

    return domain == CertDomain.CABForumBR
        ? browserForumInstances.get(certLevel) : rfc5280Instances.get(certLevel);
  } // method getExtensionSpec

  private static class Rfc5280 extends ExtensionSpec {

    private static final Set<Asn1Oid> REQUIRED_EXTENSIONS =
        Collections.emptySet();

    private static final Set<Asn1Oid> CRITICAL_ONLY_EXTENSIONS =
        Set.of(
            ExtensionID.keyUsage.oid(),
            ExtensionID.policyMappings.oid(),
            ExtensionID.nameConstraints.oid(),
            ExtensionID.policyConstraints.oid(),
            ExtensionID.inhibitAnyPolicy.oid(),
            ExtensionID.CCC_K_VehicleCert.oid(),
            ExtensionID.CCC_F_External_CACert.oid(),
            ExtensionID.CCC_E_Instance_CACert.oid(),
            ExtensionID.CCC_H_EndpointCert.oid(),
            ExtensionID.CCC_P_VehicleOEMEncCert.oid(),
            ExtensionID.CCC_Q_VehicleOEMSigCert.oid(),
            ExtensionID.CCC_DeviceEncCert.oid(),
            ExtensionID.CCC_VehicleIntermediateCert.oid(),
            ExtensionID.CCC_J_VehicleOEMCACert.oid(),
            ExtensionID.CCC_M_VehicleOEMCACert.oid(),
            ExtensionID.CCC_R_CertificationBodyCert.oid(),
            ExtensionID.CCC_S_SBxDKisIntermediateCACert.oid(),
            ExtensionID.CCC_T_SBxDKisEndpointCert.oid(),
            ExtensionID.CCC_U_SBxDKisRootCACert.oid());

    private static final Set<Asn1Oid>
        NON_CRITICAL_ONLY_EXTENSIONS = Set.of(
            ExtensionID.authorityKeyIdentifier.oid(),
            ExtensionID.subjectKeyIdentifier.oid(),
            ExtensionID.issuerAltName.oid(),
            ExtensionID.subjectDirectoryAttributes.oid(),
            ExtensionID.freshestCRL.oid(),
            ExtensionID.authorityInfoAccess.oid(),
            ExtensionID.subjectInfoAccess.oid(),
            ExtensionID.tlsFeature.oid(),
            ExtensionID.signedCertificateTimestampList.oid(),
            ExtensionID.microsoft_CertificateTemplateName.oid(),
            ExtensionID.microsoft_CertificateTemplateInformation.oid(),
            ExtensionID.microsoft_SID.oid(),
            ExtensionID.CN_residentIdCardNumber.oid(),
            ExtensionID.CN_passportNumber.oid(),
            ExtensionID.CN_socialInsuranceNumber.oid(),
            ExtensionID.CN_UnifiedSocialCreditCode.oid(),
            ExtensionID.SPDM_Extension.oid(),
            ExtensionID.STIR_TNAuthList.oid(),
            ExtensionID.STIR_JWTClaimConstraints.oid(),
            ExtensionID.MRTD_DocumentTypeList.oid()
        );

    private static final Set<Asn1Oid> NON_REQUEST_EXTENSIONS =
        Set.of(ExtensionID.authorityKeyIdentifier.oid(),
            ExtensionID.issuerAltName.oid(),
            ExtensionID.crlDistributionPoints.oid(),
            ExtensionID.authorityInfoAccess.oid(),
            ExtensionID.freshestCRL.oid(),
            ExtensionID.signedCertificateTimestampList.oid(),
            ExtensionID.inhibitAnyPolicy.oid(),
            ExtensionID.ocspNoCheck.oid(),
            ExtensionID.microsoft_CertificateTemplateName.oid(),
            ExtensionID.microsoft_CertificateTemplateInformation.oid(),
            ExtensionID.CCC_K_VehicleCert.oid(),
            ExtensionID.CCC_F_External_CACert.oid(),
            ExtensionID.CCC_P_VehicleOEMEncCert.oid(),
            ExtensionID.CCC_Q_VehicleOEMSigCert.oid(),
            ExtensionID.CCC_DeviceEncCert.oid(),
            ExtensionID.CCC_VehicleIntermediateCert.oid(),
            ExtensionID.CCC_J_VehicleOEMCACert.oid(),
            ExtensionID.CCC_M_VehicleOEMCACert.oid(),
            ExtensionID.CCC_R_CertificationBodyCert.oid(),
            ExtensionID.CCC_S_SBxDKisIntermediateCACert.oid(),
            ExtensionID.CCC_U_SBxDKisRootCACert.oid(),
            ExtensionID.STIR_JWTClaimConstraints.oid(),
            ExtensionID.MRTD_NameChange.oid(),
            ExtensionID.MRTD_DocumentTypeList.oid()
            );

    @Override
    public Set<Asn1Oid> requiredExtensions() {
      return REQUIRED_EXTENSIONS;
    }

    @Override
    public boolean isCriticalOnly(Asn1Oid type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || type.on(ExtensionOIDs.id_ccc_extn);
    }

    @Override
    public boolean isNonCriticalOnly(Asn1Oid type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type);
    }

    @Override
    public boolean isNonRequest(Asn1Oid type) {
      return NON_REQUEST_EXTENSIONS.contains(type);
    }

    @Override
    public boolean isNotPermitted(Asn1Oid type) {
      return false;
    }

  } // class Rfc5280

  private static class Rfc5280RootCA extends Rfc5280 {

    private static final Set<Asn1Oid> REQUIRED_EXTENSIONS =
        Set.of(ExtensionID.basicConstraints.oid(),
            ExtensionID.subjectKeyIdentifier.oid(),
            ExtensionID.keyUsage.oid());

    private static final Set<Asn1Oid> NON_PERMITTED_EXTENSIONS =
        Set.of(ExtensionID.certificatePolicies.oid(),
            ExtensionID.extendedKeyUsage.oid(),
            // not required in RFC5280, forbidden by several national standards,
            // e.g. chinese GM/T 0015 and German Gematik.
            ExtensionID.authorityKeyIdentifier.oid());

    private static final Set<Asn1Oid> CRITICAL_ONLY_EXTENSIONS =
        Set.of(ExtensionID.basicConstraints.oid(), ExtensionID.keyUsage.oid());

    private static final Set<Asn1Oid> NON_CRITICAL_ONLY_EXTENSIONS
        = Collections.emptySet();

    private final Set<Asn1Oid> requiredExtensions;

    private Rfc5280RootCA() {
      Set<Asn1Oid> set = new HashSet<>();
      set.addAll(REQUIRED_EXTENSIONS);
      set.addAll(super.requiredExtensions());
      this.requiredExtensions = Collections.unmodifiableSet(set);
    }

    @Override
    public Set<Asn1Oid> requiredExtensions() {
      return requiredExtensions;
    }

    @Override
    public boolean isNotPermitted(Asn1Oid type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(Asn1Oid type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(Asn1Oid type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class Rfc5280RootCA

  private static class Rfc5280SubCA extends Rfc5280 {

    private static final Set<Asn1Oid> REQUIRED_EXTENSIONS =
        Set.of(ExtensionID.basicConstraints.oid(),
            ExtensionID.subjectKeyIdentifier.oid(), ExtensionID.keyUsage.oid());

    private static final Set<Asn1Oid> NON_PERMITTED_EXTENSIONS
        = Collections.emptySet();

    private static final Set<Asn1Oid> CRITICAL_ONLY_EXTENSIONS =
        Set.of(ExtensionID.basicConstraints.oid(), // BR
            ExtensionID.keyUsage.oid(), // BR
            ExtensionID.nameConstraints.oid()); // BR

    private static final Set<Asn1Oid>
        NON_CRITICAL_ONLY_EXTENSIONS = Set.of(
            ExtensionID.certificatePolicies.oid(), // BR
            ExtensionID.crlDistributionPoints.oid(), // BR
            ExtensionID.authorityInfoAccess.oid(), // BR
            ExtensionID.extendedKeyUsage.oid()); // BR

    private final Set<Asn1Oid> requiredExtensions;

    private Rfc5280SubCA() {
      Set<Asn1Oid> set = new HashSet<>();
      set.addAll(REQUIRED_EXTENSIONS);
      set.addAll(super.requiredExtensions());
      this.requiredExtensions = Collections.unmodifiableSet(set);
    }

    @Override
    public Set<Asn1Oid> requiredExtensions() {
      return requiredExtensions;
    }

    @Override
    public boolean isNotPermitted(Asn1Oid type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(Asn1Oid type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(Asn1Oid type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class Rfc5280SubCA

  private static class Rfc5280EndEntity extends Rfc5280 {

    private static final Set<Asn1Oid> REQUIRED_EXTENSIONS =
        Set.copyOf(Collections.singletonList(ExtensionID.subjectKeyIdentifier.oid()));

    private static final Set<Asn1Oid> NON_PERMITTED_EXTENSIONS =
        Set.of(ExtensionID.policyMappings.oid(),
            ExtensionID.nameConstraints.oid(),
            ExtensionID.policyConstraints.oid());

    private static final Set<Asn1Oid> CRITICAL_ONLY_EXTENSIONS
        = Collections.emptySet();

    private static final Set<Asn1Oid> NON_CRITICAL_ONLY_EXTENSIONS
        = Collections.emptySet();

    @Override
    public Set<Asn1Oid> requiredExtensions() {
      return REQUIRED_EXTENSIONS;
    }

    @Override
    public boolean isNotPermitted(Asn1Oid type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(Asn1Oid type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(Asn1Oid type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class Rfc5280EndEntity

  private static class BrowserForumBRRootCA extends Rfc5280RootCA {

  } // class BrowserForumBRRootCA

  private static class BrowserForumBRSubCA extends Rfc5280SubCA {

    private static final Set<Asn1Oid> REQUIRED_EXTENSIONS =
        Set.of(ExtensionID.certificatePolicies.oid(), // BR
            ExtensionID.crlDistributionPoints.oid(), // BR
            ExtensionID.authorityInfoAccess.oid(), // BR
            ExtensionID.basicConstraints.oid(), // BR
            ExtensionID.keyUsage.oid()); // BR

    private static final Set<Asn1Oid> NON_PERMITTED_EXTENSIONS =
        Collections.emptySet();

    private static final Set<Asn1Oid> CRITICAL_ONLY_EXTENSIONS =
        Set.of(ExtensionID.basicConstraints.oid(), // BR
            ExtensionID.keyUsage.oid(), // BR
            ExtensionID.nameConstraints.oid()); // BR

    private static final Set<Asn1Oid>
        NON_CRITICAL_ONLY_EXTENSIONS = Set.of(
            ExtensionID.certificatePolicies.oid(), // BR
            ExtensionID.crlDistributionPoints.oid(), // BR
            ExtensionID.authorityInfoAccess.oid(), // BR
            ExtensionID.extendedKeyUsage.oid()); // BR

    private final Set<Asn1Oid> requiredExtensions;

    private BrowserForumBRSubCA() {
      Set<Asn1Oid> set = new HashSet<>();
      set.addAll(REQUIRED_EXTENSIONS);
      set.addAll(super.requiredExtensions());
      this.requiredExtensions = Collections.unmodifiableSet(set);
    }

    @Override
    public Set<Asn1Oid> requiredExtensions() {
      return requiredExtensions;
    }

    @Override
    public boolean isNotPermitted(Asn1Oid type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(Asn1Oid type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(Asn1Oid type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class BrowserForumBRSubCA

  private static class BrowserForumBREndEntity extends Rfc5280EndEntity {

    private static final Set<Asn1Oid> REQUIRED_EXTENSIONS =
        Set.of(ExtensionID.certificatePolicies.oid(), // BR
            ExtensionID.authorityInfoAccess.oid(), // BR
            ExtensionID.extendedKeyUsage.oid(), // BR
            ExtensionID.subjectAlternativeName.oid()); // BR

    private static final Set<Asn1Oid> NON_PERMITTED_EXTENSIONS =
        Collections.emptySet();

    private static final Set<Asn1Oid> CRITICAL_ONLY_EXTENSIONS =
        Collections.emptySet();

    private static final Set<Asn1Oid>
        NON_CRITICAL_ONLY_EXTENSIONS = Set.of(
            ExtensionID.certificatePolicies.oid(), // BR
            ExtensionID.crlDistributionPoints.oid(), // BR
            ExtensionID.authorityInfoAccess.oid()); // BR

    private final Set<Asn1Oid> requiredExtensions;

    private BrowserForumBREndEntity() {
      Set<Asn1Oid> set = new HashSet<>();
      set.addAll(REQUIRED_EXTENSIONS);
      set.addAll(super.requiredExtensions());
      this.requiredExtensions = Collections.unmodifiableSet(set);
    }

    @Override
    public Set<Asn1Oid> requiredExtensions() {
      return requiredExtensions;
    }

    @Override
    public boolean isNotPermitted(Asn1Oid type) {
      return NON_PERMITTED_EXTENSIONS.contains(type) || super.isNotPermitted(type);
    }

    @Override
    public boolean isCriticalOnly(Asn1Oid type) {
      return CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isCriticalOnly(type);
    }

    @Override
    public boolean isNonCriticalOnly(Asn1Oid type) {
      return NON_CRITICAL_ONLY_EXTENSIONS.contains(type) || super.isNonCriticalOnly(type);
    }

  } // class BrowserForumBREndEntity

}
