// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.util.*;

import java.util.Collections;
import java.util.Set;

/**
 * Management Entry CA-has-Requestor.
 * @author Lijun Liao (xipki)
 *
 */

public class CaHasRequestorEntry extends MgmtEntry {

  private NameId requestorIdent;

  private int permission;

  private Set<String> profiles;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CaHasRequestorEntry() {
  }

  public CaHasRequestorEntry(NameId requestorIdent) {
    this.requestorIdent = Args.notNull(requestorIdent, "requestorIdent");
  }

  public int getPermission() {
    return permission;
  }

  public void setPermission(int permission) {
    this.permission = permission;
  }

  public NameId getRequestorIdent() {
    return requestorIdent;
  }

  public void setRequestorIdent(NameId requestorIdent) {
    this.requestorIdent = requestorIdent;
  }

  public void setProfiles(Set<String> profiles) {
    if (CollectionUtil.isEmpty(profiles)) {
      this.profiles = Collections.emptySet();
    } else {
      this.profiles = CollectionUtil.unmodifiableSet(CollectionUtil.toLowerCaseSet(profiles));
    }
  }

  public Set<String> getProfiles() {
    return profiles;
  }

  public boolean isCertprofilePermitted(String certprofile) {
    if (CollectionUtil.isEmpty(profiles)) {
      return false;
    }

    return profiles.contains("all") || profiles.contains(certprofile.toLowerCase());
  }

  public boolean isPermitted(int permission) {
    return PermissionConstants.contains(this.permission, permission);
  }

  @Override
  public String toString() {
    return toString("");
  }

  public String toString(String indent) {
    return indent + "requestor:  " + requestorIdent +
        "\n" + indent + "profiles:   " + profiles +
        "\n" + indent + "permission: " + PermissionConstants.permissionToString(permission);
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
        && (permission == obj.permission)
        && CompareUtil.equalsObject(profiles, obj.profiles);
  }

  @Override
  public int hashCode() {
    return requestorIdent.hashCode();
  }

}
