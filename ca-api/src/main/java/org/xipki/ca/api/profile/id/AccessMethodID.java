// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Access Method ID.
 *
 * @author Lijun Liao (xipki)
 */
public class AccessMethodID extends AbstractID {

  private static final Map<String, AccessMethodID> typeMap = new HashMap<>();

  // 1.3.6.1.5.5.7.48.1, id-ad-ocsp, id-pkix-ocsp
  public static final AccessMethodID ocsp = initOf("1.3.6.1.5.5.7.48.1", "OCSP", "pkix-ocsp");

  // 1.3.6.1.5.5.7.48.2, CA Issuers, id-ad-caIssuers, caIssuers
  public static final AccessMethodID caIssuers = initOf( "1.3.6.1.5.5.7.48.2", "CAIssuers");

  // 1.3.6.1.5.5.7.48.3, Time Stamping, id-ad-timeStamping, timeStamping
  public static final AccessMethodID timeStamping = initOf(
      "1.3.6.1.5.5.7.48.3", "timeStamping");

  // 1.3.6.1.5.5.7.48.5, CA Repository, id-ad-caRepository
  public static final AccessMethodID caRepository = initOf(
      "1.3.6.1.5.5.7.48.5", "CARepository");

  private AccessMethodID(Asn1Oid oid, List<String> aliases) {
    super(oid, aliases);
  }

  private static AccessMethodID initOf(String oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      l.addAll(Arrays.asList(aliases));
    }
    l.add(oid);
    return addToMap(new AccessMethodID(new Asn1Oid(oid), l), typeMap);
  }

  public static AccessMethodID ofOid(Asn1Oid oid) {
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
      return ofOid(new Asn1Oid(c14n));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
