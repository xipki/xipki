/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt;

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
    private Permission(String permission)
    {
        this.permission = permission;
    }

    public String getPermission()
    {
        return permission;
    }

    public static Permission getPermission(String permission)
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
}
