// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.misc.StringUtil;

import java.util.Collections;
import java.util.List;

/**
 * Management Entry CA-has-Requestor.
 * @author Lijun Liao (xipki)
 */

public class CaHasRequestorEntry extends MgmtEntry {

  private final NameId requestorIdent;

  private final Permissions permissions;

  private final List<String> profiles;

  public CaHasRequestorEntry(NameId requestorIdent,
                             Permissions permissions, List<String> profiles) {
    this.requestorIdent = Args.notNull(requestorIdent, "requestorIdent");
    this.permissions = permissions;
    if (CollectionUtil.isEmpty(profiles)) {
      this.profiles = Collections.emptyList();
    } else {
      this.profiles = CollectionUtil.unmodifiableList(
          StringUtil.lowercase(profiles));
    }
  }

  public Permissions getPermissions() {
    return permissions;
  }

  public NameId getRequestorIdent() {
    return requestorIdent;
  }

  public List<String> getProfiles() {
    return profiles;
  }

  public boolean isCertprofilePermitted(String certprofile) {
    if (CollectionUtil.isEmpty(profiles)) {
      return false;
    }

    return profiles.contains("all")
        || profiles.contains(certprofile.toLowerCase());
  }

  public boolean isPermitted(int permission) {
    return permissions.isPermitted(permission);
  }

  @Override
  public String toString() {
    return toString("");
  }

  public String toString(String indent) {
    return indent + "requestor:  " + requestorIdent +
        "\n" + indent + "profiles:   " + profiles +
        "\n" + indent + "permission: " + permissions;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof CaHasRequestorEntry)) {
      return false;
    }

    return equals((CaHasRequestorEntry) obj, false);
  }

  public boolean equals(CaHasRequestorEntry obj, boolean ignoreId) {
    return (obj != null)
        && requestorIdent.equals(obj.requestorIdent, ignoreId)
        && CompareUtil.equals(permissions, obj.permissions)
        && CompareUtil.equals(profiles, obj.profiles);
  }

  @Override
  public int hashCode() {
    return requestorIdent.hashCode();
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap()
        .put("requestorIdent", requestorIdent.toCodec())
        .putStrings("permissions", permissions.toPermissionTexts())
        .putStrings("profiles", profiles);
  }

  public static CaHasRequestorEntry parse(JsonMap json) throws CodecException {
    return new CaHasRequestorEntry(
        NameId.parse(json.getNnMap("requestorIdent")),
        Permissions.parse(json.getList("permissions")),
        json.getStringList("profiles"));
  }

}
