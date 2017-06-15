/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.mgmt.api;

import java.util.Set;

import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.api.NameId;

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

    public int getPermission() {
        return permission;
    }

    public void setPermission(final int permission) {
        this.permission = permission;
    }

    public NameId getUserIdent() {
        return userIdent;
    }

    public void setProfiles(final Set<String> profiles) {
        this.profiles = CollectionUtil.unmodifiableSet(CollectionUtil.toUpperCaseSet(profiles));
    }

    public Set<String> getProfiles() {
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
