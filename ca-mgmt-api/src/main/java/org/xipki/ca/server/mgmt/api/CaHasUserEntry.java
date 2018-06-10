/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server.mgmt.api;

import java.util.Set;

import org.xipki.ca.api.NameId;
import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CaHasUserEntry {

  private final NameId userIdent;

  private int permission;

  private Set<String> profiles;

  public CaHasUserEntry(NameId userIdent) {
    this.userIdent = ParamUtil.requireNonNull("userIdent", userIdent);
  }

  public int getPermission() {
    return permission;
  }

  public void setPermission(int permission) {
    this.permission = permission;
  }

  public NameId getUserIdent() {
    return userIdent;
  }

  public void setProfiles(Set<String> profiles) {
    this.profiles = CollectionUtil.unmodifiableSet(CollectionUtil.toLowerCaseSet(profiles));
  }

  public Set<String> getProfiles() {
    return profiles;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjectsCap(200, "user: ", userIdent, "\nprofiles: ", profiles,
        "\npermission: ", PermissionConstants.permissionToString(permission));
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof CaHasUserEntry)) {
      return false;
    }

    return equals((CaHasUserEntry) obj, false);
  }

  public boolean equals(CaHasUserEntry obj, boolean ignoreId) {
    return (obj != null)
        && userIdent.equals(obj.userIdent, ignoreId)
        && (permission == obj.permission)
        && CompareUtil.equalsObject(profiles, obj.profiles);
  }

  @Override
  public int hashCode() {
    return userIdent.hashCode();
  }

}
