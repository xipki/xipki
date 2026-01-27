// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.ca.api.profile.id.ExtendedKeyUsageID;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.certprofile.xijson.conf.ConstantExtnValue;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.ca.certprofile.xijson.conf.extn.*;
import org.xipki.security.OIDs;
import org.xipki.security.TlsExtensionType;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.type.TripleState;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Extension builder for json configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class ExtensionConfBuilder {

  private static final Set<ExtensionID> REQUIRED_REQUEST_EXTENSIONS;

  private static final Set<ExtensionID> OPTIONAL_REQUEST_EXTENSIONS;

  static {
    REQUIRED_REQUEST_EXTENSIONS = CollectionUtil.asUnmodifiableSet(
        ExtensionID.subjectAltName,
        ExtensionID.subjectInfoAccess);

    OPTIONAL_REQUEST_EXTENSIONS = CollectionUtil.asUnmodifiableSet(
        ExtensionID.keyUsage, ExtensionID.extKeyUsage);
  } // method static

  public static List<ExtensionType> createConstantExtensions() {
    List<ExtensionType> list = new LinkedList<>();

    ExtensionType extn = new ExtensionType(ExtensionID.inhibitAnyPolicy,
        true, true);

    ConstantExtnValue constantExtnValue = new ConstantExtnValue(
        ConstantExtnValue.Type.INTEGER, "1");
    extn.setConstant(constantExtnValue);

    list.add(extn);
    return list;
  } // method createConstantExtensions

  public static ExtensionType createExtension(
      ExtensionID type, boolean required, boolean critical) {
    ExtensionType ret = new ExtensionType(type, critical, required);

    if (REQUIRED_REQUEST_EXTENSIONS.contains(type)) {
      ret.setInRequest(TripleState.required);
    } else if (OPTIONAL_REQUEST_EXTENSIONS.contains(type)) {
      ret.setInRequest(TripleState.optional);
    }

    return ret;
  }

  public static KeyUsage createKeyUsage(
      org.xipki.security.KeyUsage[] requiredUsages,
      org.xipki.security.KeyUsage[] optionalUsages) {
    SingleKeyUsages singleKeyUsages = new SingleKeyUsages(null,
        (requiredUsages == null) ? null : Arrays.asList(requiredUsages),
        (optionalUsages == null) ? null : Arrays.asList(optionalUsages));

    return new KeyUsage(List.of(singleKeyUsages));
  } // method createKeyUsage

  public static AuthorityInfoAccess createAuthorityInfoAccess() {
    return new AuthorityInfoAccess(true, true);
  } // method createAuthorityInfoAccess

  public static BasicConstraints createBasicConstraints(int pathLen) {
    return new BasicConstraints(pathLen);
  }

  public static ExtendedKeyUsage createExtendedKeyUsage(
      ExtendedKeyUsageID[] requiredUsages,
      ExtendedKeyUsageID[] optionalUsages) {
    return new ExtendedKeyUsage(
        (requiredUsages == null) ? null : Arrays.asList(requiredUsages),
        (optionalUsages == null) ? null : Arrays.asList(optionalUsages));
  } // method createExtendedKeyUsage

  public static CertificatePolicies createCertificatePolicies(
      Map<CertificatePolicyID, String> policies) {
    if (policies == null || policies.isEmpty()) {
      return null;
    }

    List<CertificatePolicies.CertificatePolicyInformationType> pis
        = new ArrayList<>(policies.size());
    for (CertificatePolicyID oid : policies.keySet()) {
      List<CertificatePolicies.PolicyQualifier> qualifiers = null;
      String cpsUri = policies.get(oid);
      if (cpsUri != null) {
        CertificatePolicies.PolicyQualifier qualifier =
            new CertificatePolicies.PolicyQualifier(
                CertificatePolicies.PolicyQualifierType.cpsUri, cpsUri);
        qualifiers = List.of(qualifier);
      }

      CertificatePolicies.CertificatePolicyInformationType single =
          new CertificatePolicies.CertificatePolicyInformationType(
              oid, qualifiers);
      pis.add(single);
    }

    return new CertificatePolicies(pis);
  } // method createCertificatePolicies

  public static PolicyMappings.PolicyIdMappingType createPolicyIdMapping(
      CertificatePolicyID issuerPolicyId, CertificatePolicyID subjectPolicyId) {
    return new PolicyMappings.PolicyIdMappingType(
        issuerPolicyId, subjectPolicyId);
  } // method createPolicyIdMapping

  public static PolicyConstraints createPolicyConstraints(
      Integer inhibitPolicyMapping, Integer requireExplicitPolicy) {
    return new PolicyConstraints(
        requireExplicitPolicy, inhibitPolicyMapping);
  } // method createPolicyConstraints

  public static NameConstraints createNameConstraints() {
    List<GeneralSubtreeType> permitted = new LinkedList<>();
    permitted.add(GeneralSubtreeType.ofDirectoryName(
        "O=myorg organization, C=DE"));

    List<GeneralSubtreeType> excluded = new LinkedList<>();
    excluded.add(GeneralSubtreeType.ofDirectoryName(
        "OU=bad OU, O=myorg organization, C=DE"));

    return new NameConstraints(permitted, excluded);
  } // method createNameConstraints

  public static InhibitAnyPolicy createInhibitAnyPolicy(int skipCerts) {
    return new InhibitAnyPolicy(skipCerts);
  } // method createInhibitAnyPolicy

  public static Map<String, String> createDescription(String details) {
    Map<String, String> map = new HashMap<>();
    map.put("category", "A");
    map.put("details", details);
    return map;
  } // method createDescription

  public static TlsFeature createTlsFeature(TlsExtensionType... features) {
    List<TlsExtensionType> exts = Arrays.asList(features);
    Collections.sort(exts);

    List<Integer> featureCodes = new ArrayList<>(features.length);
    for (TlsExtensionType m : exts) {
      featureCodes.add(m.getCode());
    }

    return new TlsFeature(featureCodes);
  } // method createTlsFeature

  public static SmimeCapabilities createSmimeCapabilities() {
    // DES-EDE3-CBC
    SmimeCapabilities.SmimeCapability cap1 =
        new SmimeCapabilities.SmimeCapability(OIDs.Algo.id_DES_EDE3_CBC, null);

    // RC2-CBC keysize 128
    SmimeCapabilities.SmimeCapability cap2 =
        new SmimeCapabilities.SmimeCapability(OIDs.Algo.id_RC2_CBC, 128);

    // RC2-CBC keysize 64
    SmimeCapabilities.SmimeCapability cap3 =
        new SmimeCapabilities.SmimeCapability(OIDs.Algo.id_RC2_CBC, 64);

    return new SmimeCapabilities(Arrays.asList(cap1, cap2, cap3));
  } // method createSmimeCapabilities

}
