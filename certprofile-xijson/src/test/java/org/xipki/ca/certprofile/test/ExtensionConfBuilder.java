// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.xipki.ca.api.profile.id.CertificatePolicyID;
import org.xipki.ca.api.profile.id.ExtendedKeyUsageID;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.certprofile.xijson.conf.ConstantExtnValue;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.ca.certprofile.xijson.conf.extn.*;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.TlsExtensionType;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.codec.TripleState;

import java.io.IOException;
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

    for (ConstantExtnValue.Type type : ConstantExtnValue.Type.values()) {
      ConstantExtnValue constValue;
      ExtensionID extnId;
      switch (type) {
        case INTEGER: {
          extnId = ExtensionID.inhibitAnyPolicy;
          constValue = new ConstantExtnValue(type, "1");
          break;
        }
        case PRINTABLE: {
          extnId = ExtensionID.ofOid(new ASN1ObjectIdentifier("1.2.3.4.5.2"));
          constValue = new ConstantExtnValue(type, "my printable string");
          break;
        }
        case UTF8: {
          extnId = ExtensionID.ofOid(new ASN1ObjectIdentifier("1.2.3.4.5.3"));
          constValue = new ConstantExtnValue(type, "my UTF8 string");
          break;
        }
        case BITSTRING: {
          extnId = ExtensionID.ofOid(new ASN1ObjectIdentifier("1.2.3.4.5.4"));
          byte[] value = new byte[4];
          Arrays.fill(value, (byte) 0x11);
          constValue = new ConstantExtnValue(type, value);
          break;
        }
        case OCTETSTRING: {
          extnId = ExtensionID.ofOid(new ASN1ObjectIdentifier("1.2.3.4.5.5"));
          byte[] value = new byte[4];
          Arrays.fill(value, (byte) 0x22);
          constValue = new ConstantExtnValue(type, value);
          break;
        }
        case ASN1: {
          extnId = ExtensionID.ofOid(new ASN1ObjectIdentifier("1.2.3.4.5.6"));
          try {
            constValue = new ConstantExtnValue(type,
                DERNull.INSTANCE.getEncoded());
          } catch (IOException e) {
            throw new RuntimeException(e);
          }
          break;
        }
        default:
          throw new IllegalStateException("shall not reach here");
      }

      ExtensionType extn = new ExtensionType(extnId, true, true);
      extn.setConstant(constValue);
      list.add(extn);
    }

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
      org.xipki.security.KeyUsage[] optionalUsages,
      List<KeySpec> keySpecs) {
    List<org.xipki.security.KeyUsage> reqSignUsages = new ArrayList<>();
    List<org.xipki.security.KeyUsage> reqEncUsages = new ArrayList<>();
    List<org.xipki.security.KeyUsage> reqKAUsages = new ArrayList<>();

    if (requiredUsages != null) {
      for (org.xipki.security.KeyUsage usage : requiredUsages) {
        if (isSignUsage(usage)) {
          reqSignUsages.add(usage);
        } else if (isEncUsage(usage)){
          reqEncUsages.add(usage);
        } else if (isKAUsage(usage)) {
          reqKAUsages.add(usage);
        }
      }
    }

    List<org.xipki.security.KeyUsage> optSignUsages = new ArrayList<>();
    List<org.xipki.security.KeyUsage> optEncUsages = new ArrayList<>();
    List<org.xipki.security.KeyUsage> optKAUsages = new ArrayList<>();

    if (optionalUsages != null) {
      for (org.xipki.security.KeyUsage usage : optionalUsages) {
        if (isSignUsage(usage)) {
          optSignUsages.add(usage);
        } else if (isEncUsage(usage)){
          optEncUsages.add(usage);
        } else if (isKAUsage(usage)) {
          optKAUsages.add(usage);
        }
      }
    }

    List<KeySpec> signOnlyKeySpecs = new ArrayList<>();
    List<KeySpec> encOnlyKeySpecs  = new ArrayList<>();

    List<KeySpec> signEncKeySpecs = new ArrayList<>();
    List<KeySpec> encKaKeySpecs = new ArrayList<>();
    List<KeySpec> allKeySpecs = new ArrayList<>();

    for (KeySpec keySpec : keySpecs) {
      if (keySpec.isRSA()) {
        signEncKeySpecs.add(keySpec);
      } else if (keySpec.isWeierstrassEC()) {
        allKeySpecs.add(keySpec);
      } else if (keySpec.isEdwardsEC() || keySpec.isMldsa() ||
          keySpec.isCompositeMLDSA()) {
        signOnlyKeySpecs.add(keySpec);
      } else if (keySpec.isMontgomeryEC()) {
        encKaKeySpecs.add(keySpec);
      } else if (keySpec.isMlkem() || keySpec.isCompositeMLKEM()) {
        encOnlyKeySpecs.add(keySpec);
      } else {
        throw new IllegalArgumentException("unknown KeySpec " + keySpec);
      }
    }

    List<SingleKeyUsages> list = new ArrayList<>();

    if (!signOnlyKeySpecs.isEmpty()) {
      list.add(new SingleKeyUsages(signOnlyKeySpecs,
                reqSignUsages, optSignUsages));
    }

    if (!encOnlyKeySpecs.isEmpty()) {
      list.add(new SingleKeyUsages(encOnlyKeySpecs,
          reqEncUsages, optEncUsages));
    }

    if (!signEncKeySpecs.isEmpty()) {
      List<org.xipki.security.KeyUsage> reqUsages = new ArrayList<>();
      reqUsages.addAll(reqEncUsages);
      reqUsages.addAll(reqSignUsages);

      List<org.xipki.security.KeyUsage> optUsages = new ArrayList<>();
      optUsages.addAll(optEncUsages);
      optUsages.addAll(optSignUsages);

      list.add(new SingleKeyUsages(signEncKeySpecs, reqUsages, optUsages));
    }

    if (!encKaKeySpecs.isEmpty()) {
      List<org.xipki.security.KeyUsage> reqUsages = new ArrayList<>();
      reqUsages.addAll(reqEncUsages);
      reqUsages.addAll(reqKAUsages);

      List<org.xipki.security.KeyUsage> optUsages = new ArrayList<>();
      optUsages.addAll(optEncUsages);
      optUsages.addAll(optKAUsages);

      list.add(new SingleKeyUsages(encKaKeySpecs, reqUsages, optUsages));
    }

    if (!allKeySpecs.isEmpty()) {
      List<org.xipki.security.KeyUsage> reqUsages = new ArrayList<>();
      reqUsages.addAll(reqEncUsages);
      reqUsages.addAll(reqSignUsages);
      reqUsages.addAll(reqKAUsages);

      List<org.xipki.security.KeyUsage> optUsages = new ArrayList<>();
      optUsages.addAll(optEncUsages);
      optUsages.addAll(optSignUsages);
      optUsages.addAll(optKAUsages);

      list.add(new SingleKeyUsages(allKeySpecs, reqUsages, optUsages));
    }

    // merge entries with same key-usages
    int size = list.size();
    if (size > 1) {
      List<SingleKeyUsages> newList = new ArrayList<>(size);
      newList.add(list.get(0));
      for (int i = 1; i < size; i++) {
        SingleKeyUsages u = list.get(i);
        SingleKeyUsages nu = null;
        for (SingleKeyUsages v : newList) {
          if (u.required().equals(v.required()) &&
              u.optional().equals(v.optional())) {
            nu = v;
            break;
          }
        }

        if (nu == null) {
          newList.add(u);
        } else {
          nu.appliesTo().addAll(u.appliesTo());
        }
      }

      list = newList;
    }

    if (list.size() == 1) {
      list.get(0).setAppliesTo(null);
    }

    // set empty list to null
    for (SingleKeyUsages v : list) {
      if (CollectionUtil.isEmpty(v.appliesTo())) {
        v.setAppliesTo(null);
      }

      if (CollectionUtil.isEmpty(v.required())) {
        v.setRequired(null);
      }

      if (CollectionUtil.isEmpty(v.optional())) {
        v.setOptional(null);
      }
    }

    return new KeyUsage(list);
  } // method createKeyUsage

  private static boolean isSignUsage(org.xipki.security.KeyUsage usage) {
    switch (usage) {
      case digitalSignature:
      case contentCommitment:
      case keyCertSign:
      case cRLSign:
        return true;
      default:
        return false;
    }
  }

  private static boolean isEncUsage(org.xipki.security.KeyUsage usage) {
    switch (usage) {
      case dataEncipherment:
      case decipherOnly:
      case encipherOnly:
      case keyEncipherment:
        return true;
      default:
        return false;
    }
  }

  private static boolean isKAUsage(org.xipki.security.KeyUsage usage) {
    return usage == org.xipki.security.KeyUsage.keyAgreement;
  }

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
      featureCodes.add(m.code());
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
