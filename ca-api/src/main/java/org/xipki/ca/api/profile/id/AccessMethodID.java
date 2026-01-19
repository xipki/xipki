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
public class AccessMethodID extends AbstractID {

  private static final Map<String, AccessMethodID> typeMap = new HashMap<>();

  // 1.3.6.1.5.5.7.48.1, id-ad-ocsp, id-pkix-ocsp
  public static final AccessMethodID ocsp = initOf("1.3.6.1.5.5.7.48.1",
      "OCSP", "pkix-ocsp");

  // 1.3.6.1.5.5.7.48.2, CA Issuers, id-ad-caIssuers, caIssuers
  public static final AccessMethodID caIssuers = initOf(
      "1.3.6.1.5.5.7.48.2", "CAIssuers");

  // 1.3.6.1.5.5.7.48.3, Time Stamping, id-ad-timeStamping, timeStamping
  public static final AccessMethodID timeStamping = initOf(
      "1.3.6.1.5.5.7.48.3", "timeStamping");

  // 1.3.6.1.5.5.7.48.5, CA Repository, id-ad-caRepository
  public static final AccessMethodID caRepository = initOf(
      "1.3.6.1.5.5.7.48.5", "CARepository");

  private AccessMethodID(ASN1ObjectIdentifier oid, List<String> aliases) {
    super(oid, aliases);
  }

  private static AccessMethodID initOf(String oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      l.addAll(Arrays.asList(aliases));
    }
    l.add(oid);
    return addToMap(new AccessMethodID(new ASN1ObjectIdentifier(oid), l),
        typeMap);
  }

  public static AccessMethodID ofOid(ASN1ObjectIdentifier oid) {
    Args.notNull(oid, "oid");
    AccessMethodID attr = typeMap.get(oid.getId());
    if (attr == null) {
      attr = new AccessMethodID(oid, Collections.singletonList(oid.getId()));
    }
    return attr;
  }

  public static AccessMethodID ofOidOrName(String oidOrName) {
    String c14n = canonicalizeAlias(Args.notNull(oidOrName, "oidOrName"));
    AccessMethodID id = ofOidOrName(typeMap, c14n);
    if (id != null) {
      return id;
    }

    try {
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(c14n);
      return ofOid(oid);
    } catch (RuntimeException e) {
      return null;
    }
  }

}
