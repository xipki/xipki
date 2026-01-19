// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.type;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * OID with description.
 *
 * @author Lijun Liao (xipki)
 */
public class DescribableOid extends V1Describable {

  private final String oid;

  public DescribableOid(String description, String oid) {
    super(description);
    this.oid = Args.notBlank(oid, "oid");
  }

  public String getOid() {
    return oid;
  }

  public ASN1ObjectIdentifier oid() {
    return new ASN1ObjectIdentifier(oid);
  }

  public static DescribableOid parse(JsonMap json) throws CodecException {
    return new DescribableOid(json.getString("description"),
        json.getNnString("oid"));
  }

  public static DescribableOid parseNn(JsonMap json, String key)
      throws CodecException {
    DescribableOid v = parse(json, key);
    if (v == null) {
      throw new CodecException(key + " is not present");
    }
    return v;
  }

  public static DescribableOid parse(JsonMap json, String key)
      throws CodecException {
    JsonMap map = json.getMap(key);
    return (map == null) ? null : parse(map);
  }

  public static List<DescribableOid> parseList(JsonList json)
      throws CodecException {
    List<DescribableOid> ret = new ArrayList<>(json.size());
    for (JsonMap v : json.toMapList()) {
      ret.add(DescribableOid.parse(v));
    }
    return ret;
  }

} // class DescribableOid
