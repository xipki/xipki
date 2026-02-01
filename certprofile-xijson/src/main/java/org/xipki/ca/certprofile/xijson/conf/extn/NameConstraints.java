// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.List;

/**
 * Extension NameConstraints.
 * Only for CA, at least one of permittedSubtrees and excludedSubtrees must
 * be present.
 * @author Lijun Liao (xipki)
 */
public class NameConstraints implements JsonEncodable {

  private final List<GeneralSubtreeType> permittedSubtrees;

  private final List<GeneralSubtreeType> excludedSubtrees;

  public NameConstraints(List<GeneralSubtreeType> permittedSubtrees,
                         List<GeneralSubtreeType> excludedSubtrees) {
    if (CollectionUtil.isEmpty(permittedSubtrees)
        && CollectionUtil.isEmpty(excludedSubtrees)) {
      throw new IllegalArgumentException(
          "permittedSubtrees and excludedSubtrees may not be both null");
    }

    this.permittedSubtrees = permittedSubtrees;
    this.excludedSubtrees  = excludedSubtrees;
  }

  public List<GeneralSubtreeType> permittedSubtrees() {
    return permittedSubtrees;
  }

  public List<GeneralSubtreeType> excludedSubtrees() {
    return excludedSubtrees;
  }

  public org.bouncycastle.asn1.x509.NameConstraints toNameConstraints() {
    GeneralSubtree[] permitted = buildX509GeneralSubtrees(permittedSubtrees);
    GeneralSubtree[] excluded  = buildX509GeneralSubtrees(excludedSubtrees);
    return (permitted == null && excluded == null) ? null
        : new org.bouncycastle.asn1.x509.NameConstraints(permitted, excluded);
  }

  private static GeneralSubtree[] buildX509GeneralSubtrees(
      List<GeneralSubtreeType> subtrees) {
    if (CollectionUtil.isEmpty(subtrees)) {
      return null;
    }

    final int n = subtrees.size();
    GeneralSubtree[] ret = new GeneralSubtree[n];
    for (int i = 0; i < n; i++) {
      ret[i] = buildX509GeneralSubtree(subtrees.get(i));
    }

    return ret;
  }

  private static GeneralSubtree buildX509GeneralSubtree(
      GeneralSubtreeType type) {
    GeneralSubtreeType baseType = Args.notNull(type, "type");
    GeneralName base;
    if (baseType.directoryName() != null) {
      base = new GeneralName(X509Util.reverse(
          new X500Name(baseType.directoryName())));
    } else if (baseType.dnsName() != null) {
      base = new GeneralName(GeneralName.dNSName, baseType.dnsName());
    } else if (baseType.ipAddress() != null) {
      base = new GeneralName(GeneralName.iPAddress, baseType.ipAddress());
    } else if (baseType.rfc822Name() != null) {
      base = new GeneralName(GeneralName.rfc822Name, baseType.rfc822Name());
    } else if (baseType.uri() != null) {
      base = new GeneralName(GeneralName.uniformResourceIdentifier,
          baseType.uri());
    } else {
      throw new IllegalStateException(
          "should not reach here, unknown child of GeneralSubtreeType");
    }

    return new GeneralSubtree(base, null, null);
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEncodables("permittedSubtrees", permittedSubtrees)
        .putEncodables("excludedSubtrees", excludedSubtrees);
  }

  public static NameConstraints parse(JsonMap json) throws CodecException {
    List<GeneralSubtreeType> permittedSubtrees = null;
    JsonList list = json.getList("permittedSubtrees");
    if (list != null) {
      permittedSubtrees = GeneralSubtreeType.parse(list);
    }

    List<GeneralSubtreeType> excludedSubtrees = null;
    list = json.getList("excludedSubtrees");
    if (list != null) {
      excludedSubtrees = GeneralSubtreeType.parse(list);
    }

    return new NameConstraints(permittedSubtrees, excludedSubtrees);
  }

} // class NameConstraints
