/*
 * Copyright 2014 xipki.org
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

package org.xipki.ca.server;

import java.util.Set;

import org.xipki.ca.common.CertBasedRequestorInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.mgmt.Permission;

public class CmpRequestorInfo extends CertBasedRequestorInfo
{
    private Set<Permission> permissions;
    private Set<String> profiles;

    public CmpRequestorInfo(X509CertificateWithMetaInfo certificate, boolean ra)
    {
        super(certificate, ra);
    }

    public Set<Permission> getPermissions()
    {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions)
    {
        this.permissions = permissions;
    }

    public Set<String> getProfiles()
    {
        return profiles;
    }

    public void setProfiles(Set<String> profiles)
    {
        this.profiles = profiles;
    }

}
