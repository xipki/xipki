// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.util.codec.Args;

import java.util.Locale;

/**
 * @author Lijun Liao (xipki)
 */
public enum GeneralNameTag {

  otherName(0),
  rfc822Name(1),
  DNSName(2),
  x400Address(3),
  directoryName(4),
  ediPartyName(5),
  uri(6),
  IPAddress(7),
  registeredID(8);

  private final int tag;

  GeneralNameTag(int tag) {
    this.tag = tag;
  }

  public int getTag() {
    return tag;
  }

  public static GeneralNameTag ofTag(int tag) {
    for (GeneralNameTag v : values()) {
      if (tag == v.tag) {
        return v;
      }
    }
    return null;
  }

  public static GeneralNameTag getGeneralNameTag(String name) {
    name = Args.notNull(name, "name").trim();

    String c14nName = canonicalizeName(name);

    if ("uniformResourceIdentifier".equalsIgnoreCase(c14nName)) {
      return uri; // historic reason
    } else if ("x400Adress".equalsIgnoreCase(c14nName)) {
      return x400Address; // // historic reason
    }

    for (GeneralNameTag m : GeneralNameTag.values()) {
      if (c14nName.equalsIgnoreCase(m.name())) {
          return m;
      }

      if (Integer.toString(m.getTag()).equals(name)) {
        return m;
      }
    }

    throw new IllegalArgumentException("invalid GeneralNameTag " + name);
  }

  private static String canonicalizeName(String name) {
    return name.toUpperCase(Locale.ROOT)
        .replace("_", "")
        .replace(" ", "")
        .replace("-", "");
  }

} // class GeneralNameTag
