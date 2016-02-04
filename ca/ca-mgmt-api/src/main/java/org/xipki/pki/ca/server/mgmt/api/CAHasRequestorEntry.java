/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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

import java.io.Serializable;
import java.util.Collections;
import java.util.Set;

import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CAHasRequestorEntry implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String requestorName;

    private boolean ra;

    private Set<Permission> permissions;

    private Set<String> profiles;

    public CAHasRequestorEntry(
            final String requestorName) {
        ParamUtil.assertNotBlank("requestorName", requestorName);
        this.requestorName = requestorName;
    }

    public boolean isRa() {
        return ra;
    }

    public void setRa(
            final boolean ra) {
        this.ra = ra;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(
            final Set<Permission> permissions) {
        this.permissions = Collections.unmodifiableSet(permissions);
    }

    public String getRequestorName() {
        return requestorName;
    }

    public void setProfiles(
            final Set<String> profiles) {
        if (profiles == null) {
            this.profiles = Collections.emptySet();
        } else {
            this.profiles = CollectionUtil.unmodifiableSet(profiles);
        }
    }

    public Set<String> getProfiles() {
        return profiles;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(200);
        sb.append("requestor: ").append(requestorName).append(", ");
        sb.append("ra: ").append(ra).append(", ");
        sb.append("profiles: ").append(profiles).append(", ");
        sb.append("permissions: ").append(Permission.toString(permissions));
        return sb.toString();
    }

}
