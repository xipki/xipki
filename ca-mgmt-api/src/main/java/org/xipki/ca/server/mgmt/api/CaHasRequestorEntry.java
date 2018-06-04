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

import java.util.Collections;
import java.util.Set;

import org.xipki.ca.api.NameId;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaHasRequestorEntry {

  private final NameId requestorIdent;

  private boolean ra;

  private int permission;

  private Set<String> profiles;

  public CaHasRequestorEntry(NameId requestorIdent) {
    this.requestorIdent = ParamUtil.requireNonNull("requestorIdent", requestorIdent);
  }

  public boolean isRa() {
    return ra;
  }

  public void setRa(boolean ra) {
    this.ra = ra;
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
    return StringUtil.concatObjectsCap(200, "requestor: ", requestorIdent,
        ", ra: ", ra, ", profiles: ", profiles,
        ", permission: ", PermissionConstants.permissionToString(permission));
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof CaHasRequestorEntry)) {
      return false;
    }

    return equals((CaHasRequestorEntry) obj, false);
  }

  public boolean equals(CaHasRequestorEntry obj, boolean ignoreId) {
    return (obj != null)
        && (ra == obj.ra)
        && requestorIdent.equals(obj.requestorIdent, ignoreId)
        && (permission == obj.permission)
        && CompareUtil.equalsObject(profiles, obj.profiles);
  }

  @Override
  public int hashCode() {
    return requestorIdent.hashCode();
  }

}
