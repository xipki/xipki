/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.server.mgmt.api;

import java.util.Set;

import org.xipki.common.util.CollectionUtil;

/**
 * @author Lijun Liao
 */

public enum Permission
{
    ENROLL_CERT ("enroll"),
    REVOKE_CERT ("revoke"),
    UNREVOKE_CERT ("unrevoke"),
    REMOVE_CERT ("remove"),
    KEY_UPDATE ("key-update"),
    GEN_CRL ("gen-crl"),
    GET_CRL ("get-crl"),
    CROSS_CERT_ENROLL ("enroll-cross"),
    ALL("all");

    private String permission;

    private Permission(
            final String permission)
    {
        this.permission = permission;
    }

    public String getPermission()
    {
        return permission;
    }

    public static Permission getPermission(
            final String permission)
    {
        for(Permission p : values())
        {
            if(p.permission.equalsIgnoreCase(permission))
            {
                return p;
            }
        }

        return null;
    }

    public static String toString(
            final Set<Permission> permissions)
    {
        if(CollectionUtil.isEmpty(permissions))
        {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        for(Permission p : permissions)
        {
            sb.append(",");
            sb.append(p.getPermission());
        }
        return sb.substring(1); // remove the leading ",".
    }

}
