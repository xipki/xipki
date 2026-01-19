// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
public class CertificatePolicyID extends AbstractID {

  private static final Map<String, CertificatePolicyID> typeMap =
      new HashMap<>();

  // 2.5.29.32.0, Any Policy
  public static final CertificatePolicyID any =
      initOf("2.5.29.32.0", "any");

  // 2.23.140.1.2.1, Domain Validation (DV)
  public static final CertificatePolicyID domainValidated =
      initOf("2.23.140.1.2.1", "DomainValidation");

  // 2.23.140.1.2.2, Organization Validation (OV)
  public static final CertificatePolicyID organizationValidated =
      initOf("2.23.140.1.2.2", "OrganizationValidation");

  // 2.23.140.1.2.3, Individual Validation (IV)
  public static final CertificatePolicyID individualValidated =
      initOf("2.23.140.1.2.3", "IndividualValidation");

  // 2.23.140.1.1, Extended Validation (EV)
  public static final CertificatePolicyID evGuidelines =
      initOf("2.23.140.1.1", "ExtendedValidation");

  // For here the constants are still not defined in the spec
  // EN 319 411-2 (https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.03.01_60/en_31941102v020301p.pdf)
  // 0.4.0.194112.1.0
  public static final CertificatePolicyID etsi_qcp_natural =
      initOf("0.4.0.194112.1.0", "ETSI-qcp-natural");

  // 0.4.0.194112.1.1
  public static final CertificatePolicyID etsi_qcp_legal =
    initOf("0.4.0.194112.1.1", "ETSI-qcp-legal");

  // 0.4.0.194112.1.2
  public static final CertificatePolicyID etsi_qcp_natural_qscd =
      initOf("0.4.0.194112.1.2", "ETSI-qcp-natural-qscd");

  // 0.4.0.194112.1.3
  public static final CertificatePolicyID etsi_qcp_legal_qscd =
      initOf("0.4.0.194112.1.3", "ETSI-qcp-legal-qscd");

  // 0.4.0.194112.1.4
  public static final CertificatePolicyID etsi_qcp_web =
      initOf("0.4.0.194112.1.4", "ETSI-qcp-web");

  // 0.4.0.19495.3.1
  public static final CertificatePolicyID etsi_qcp_web_psd2 =
      initOf("0.4.0.19495.3.1", "ETSI-qcp-web-psd2");

  private CertificatePolicyID(ASN1ObjectIdentifier x509, List<String> aliases) {
    super(x509, aliases);
  }

  private static CertificatePolicyID initOf(String oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      l.addAll(Arrays.asList(aliases));
    }
    l.add(oid);
    return addToMap(new CertificatePolicyID(new ASN1ObjectIdentifier(oid), l),
        typeMap);
  }

  public static CertificatePolicyID ofOid(ASN1ObjectIdentifier oid) {
    Args.notNull(oid, "oid");
    CertificatePolicyID attr = ofOidOrName(typeMap, oid.getId());
    if (attr != null) {
      return attr;
    }

    return new CertificatePolicyID(oid, Collections.singletonList(oid.getId()));
  }

  public static CertificatePolicyID ofOidOrName(String oidOrName) {
    String c14n = canonicalizeAlias(Args.notNull(oidOrName, "oidOrName"));
    CertificatePolicyID id = ofOidOrName(typeMap, c14n);
    if (id != null) {
      return id;
    }

    try {
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(c14n);
      return new CertificatePolicyID(oid,
          Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
