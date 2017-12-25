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

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaHasRequestorEntry {

    private final NameId requestorIdent;

    private boolean ra;

    private int permission;

    private Set<String> profiles;

    public CaHasRequestorEntry(final NameId requestorIdent) {
        this.requestorIdent = ParamUtil.requireNonNull("requestorIdent", requestorIdent);
    }

    public boolean isRa() {
        return ra;
    }

    public void setRa(final boolean ra) {
        this.ra = ra;
    }

    public int permission() {
        return permission;
    }

    public void setPermission(final int permission) {
        this.permission = permission;
    }

    public NameId requestorIdent() {
        return requestorIdent;
    }

    public void setProfiles(final Set<String> profiles) {
        if (CollectionUtil.isEmpty(profiles)) {
            this.profiles = Collections.emptySet();
        } else {
            this.profiles = CollectionUtil.unmodifiableSet(CollectionUtil.toUpperCaseSet(profiles));
        }
    }

    public Set<String> profiles() {
        return profiles;
    }

    public boolean isCertProfilePermitted(String certprofile) {
        if (CollectionUtil.isEmpty(profiles)) {
            return false;
        }

        return profiles.contains("ALL") || profiles.contains(certprofile.toUpperCase());
    }

    public boolean isPermitted(int permission) {
        return PermissionConstants.contains(this.permission, permission);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(200);
        sb.append("requestor: ").append(requestorIdent).append("\n");
        sb.append("ra: ").append(ra).append("\n");
        sb.append("profiles: ").append(profiles).append("\n");
        sb.append("permission: ").append(permission);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CaHasRequestorEntry)) {
            return false;
        }

        CaHasRequestorEntry objB = (CaHasRequestorEntry) obj;
        if (ra != objB.ra) {
            return false;
        }

        if (!requestorIdent.equals(objB.requestorIdent)) {
            return false;
        }

        if (permission != objB.permission) {
            return false;
        }

        if (!CompareUtil.equalsObject(profiles, objB.profiles)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return requestorIdent.hashCode();
    }

}
