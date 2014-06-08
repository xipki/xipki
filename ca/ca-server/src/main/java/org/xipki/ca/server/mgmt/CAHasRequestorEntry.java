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

import java.util.Collections;
import java.util.Set;

import org.xipki.security.common.ParamChecker;

public class CAHasRequestorEntry
{
    private final String requestorName;
    private boolean ra;
    private Set<Permission> permissions;
    private Set<String> profiles;

    public CAHasRequestorEntry(String requestorName)
    {
        ParamChecker.assertNotEmpty("requestorName", requestorName);
        this.requestorName = requestorName;
    }

    public boolean isRa()
    {
        return ra;
    }

    public void setRa(boolean ra)
    {
        this.ra = ra;
    }

    public Set<Permission> getPermissions()
    {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions)
    {
        this.permissions = Collections.unmodifiableSet(permissions);
    }

    public String getRequestorName()
    {
        return requestorName;
    }

    public void setProfiles(Set<String> profiles)
    {
        this.profiles = Collections.unmodifiableSet(profiles);
    }

    public Set<String> getProfiles()
    {
        return profiles;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("requestor: ").append(requestorName).append(", ");
        sb.append("ra: ").append(ra).append(", ");
        sb.append("profiles: ").append(profiles).append(", ");
        sb.append("permissions: ").append(Permission.toString(permissions));
        return sb.toString();
    }
}
