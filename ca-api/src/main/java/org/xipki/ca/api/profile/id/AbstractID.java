// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
public class AbstractID {

  private final ASN1ObjectIdentifier oid;

  private final String mainAlias;

  private final List<String> aliases;

  protected AbstractID(ASN1ObjectIdentifier oid, List<String> aliases) {
    Args.notEmpty(aliases, "aliases");

    this.oid = Args.notNull(oid, "oid");
    this.mainAlias = aliases.get(0);

    List<String> c14nAliases = new ArrayList<>(aliases.size());
    for (String alias : aliases) {
      c14nAliases.add(canonicalizeAlias(alias));
    }

    this.aliases = Collections.unmodifiableList(c14nAliases);
  }

  protected static String canonicalizeAlias(String alias) {
    return alias.toUpperCase(Locale.ROOT)
        .replace("_", "")
        .replace(" ", "")
        .replace("-", "");
  }

  public ASN1ObjectIdentifier getOid() {
    return oid;
  }

  public String getTextOid() {
    return oid.getId();
  }

  public List<String> getAliases() {
    return aliases;
  }

  public String getMainAlias() {
    return mainAlias;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof AbstractID)) return false;

    if (!getClass().getName().equals(obj.getClass().getName())) {
      return false;
    }

    return oid.equals(((AbstractID) obj).oid);
  }

  @Override
  public int hashCode() {
    return oid.hashCode();
  }

  @Override
  public String toString() {
    return oid.getId() + " (" + mainAlias + ")";
  }

  public static List<String> toJsonStringList(List<? extends AbstractID> list) {
    List<String> ret = new ArrayList<>(list.size());
    for (AbstractID v : list) {
      ret.add(v.mainAlias);
    }
    return ret;
  }

  protected static <T extends AbstractID> T ofOidOrName(
      Map<String, T> typeMap, String oidOrName) {
    T attr = typeMap.get(oidOrName);
    if (attr != null) {
      return attr;
    }

    for (T m : typeMap.values()) {
      if (m.getAliases().contains(oidOrName)) {
        return m;
      }
    }

    return null;
  }

  protected static <T extends AbstractID> T addToMap(T t, Map<String, T> m) {
    for (String a : t.getAliases()) {
      if (m.containsKey(a)) {
        throw new IllegalArgumentException("duplicated alias " + a);
      }
      m.put(a, t);
    }
    return t;
  }

}
