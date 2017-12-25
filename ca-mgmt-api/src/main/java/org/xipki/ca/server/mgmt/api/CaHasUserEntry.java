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
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CaHasUserEntry {

    private final NameId userIdent;

    private int permission;

    private Set<String> profiles;

    public CaHasUserEntry(final NameId userIdent) {
        this.userIdent = ParamUtil.requireNonNull("userIdent", userIdent);
    }

    public int permission() {
        return permission;
    }

    public void setPermission(final int permission) {
        this.permission = permission;
    }

    public NameId userIdent() {
        return userIdent;
    }

    public void setProfiles(final Set<String> profiles) {
        this.profiles = CollectionUtil.unmodifiableSet(CollectionUtil.toUpperCaseSet(profiles));
    }

    public Set<String> profiles() {
        return profiles;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(200);
        sb.append("user: ").append(userIdent).append("\n");
        sb.append("profiles: ").append(profiles).append("\n");
        sb.append("permission: ").append(permission);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CaHasUserEntry)) {
            return false;
        }

        CaHasUserEntry objB = (CaHasUserEntry) obj;

        if (!userIdent.equals(objB.userIdent)) {
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
        return userIdent.hashCode();
    }

}
