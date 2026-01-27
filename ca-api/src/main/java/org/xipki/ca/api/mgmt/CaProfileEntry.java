// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.misc.StringUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * CA_HASH_PROFILE profile name and aliases.
 *
 * @author Lijun Liao (xipki)
 */

public class CaProfileEntry {

  private final String profileName;

  private final List<String> profileAliases;

  private final String encoded;

  public static CaProfileEntry decode(String encoded) {
    String[] tokens = encoded.split(":");
    if (tokens.length < 1) {
      throw new IllegalArgumentException("invalid encoded '" + encoded + "'");
    }
    String name = tokens[0];
    String[] list = tokens.length == 1 ? null : tokens[1].split(",");
    List<String> aliases = list == null ? null : List.of(list);
    return new CaProfileEntry(name, aliases);
  }

  public CaProfileEntry(String profileName, List<String> profileAliases) {
    this.profileName = Args.toNonBlankLower(profileName, "profileName");
    if (profileAliases == null) {
      this.profileAliases = Collections.emptyList();
    } else {
      this.profileAliases = new ArrayList<>(profileAliases.size());
      for (String alias : profileAliases) {
        String lcAlias = alias.toLowerCase(Locale.ROOT);
        if (! (this.profileName.equals(lcAlias)
                || this.profileAliases.contains(lcAlias))) {
          this.profileAliases.add(lcAlias);
        }
      }
      Collections.sort(this.profileAliases);
    }

    if (CollectionUtil.isEmpty(this.profileAliases)) {
      encoded = profileName;
    } else {
      encoded = profileName + ":" + getEncodedAliases();
    }
  }

  public String getProfileName() {
    return profileName;
  }

  public List<String> getProfileAliases() {
    return profileAliases;
  }

  public boolean containsNameOrAlias(String nameOrAlias) {
    String lcNameOrAlias = Args.toNonBlankLower(nameOrAlias, "nameOrAlias");
    return profileName.equals(lcNameOrAlias)
            || profileAliases.contains(lcNameOrAlias);
  }

  public String containedNameOrAlias(CaProfileEntry other) {
    if (containsNameOrAlias(other.profileName)) {
      return other.profileName;
    }

    for (String alias : other.getProfileAliases()) {
      if (containsNameOrAlias(alias)) {
        return alias;
      }
    }

    return null;
  }

  public String getEncodedAliases() {
    return StringUtil.collectionAsString(profileAliases, ",");
  }

  public String getEncoded() {
    return encoded;
  }

  @Override
  public String toString() {
    return encoded;
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof CaProfileEntry)) {
      return false;
    }

    return encoded.equals(((CaProfileEntry) other).encoded);
  }

  @Override
  public int hashCode() {
    return encoded.hashCode();
  }

}
