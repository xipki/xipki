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

package org.xipki.ca.server.mgmt.shell;

import java.util.HashSet;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.Permission;
import org.xipki.security.common.ConfigurationException;

@Command(scope = "ca", name = "careq-add", description="Add requestor to CA")
public class CaRequestorAddCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name",
            required = true)
    protected String           caName;

    @Option(name = "-requestor",
            required = true, description = "Required. Requestor name")
    protected String            requestorName;

    @Option(name = "-era",
            description = "Requestor as RA, the default is not as RA")
    protected Boolean            era;

    @Option(name = "-dra",
            description = "Requestor not as RA")
    protected Boolean            dra;

    @Option(name = "-permission",
            description = "Required. Permission, multi options is allowed. allowed values are " + permissionsText,
            required = true, multiValued = true)
    protected Set<String> permissions;

    @Option(name = "-profile",
            description = "Required. Profile name or 'all' for all profiles, multi options is allowed",
            required = true, multiValued = true)
    protected Set<String> profiles;

    @Override
    protected Object doExecute() throws Exception
    {
        if(era != null && dra != null )
        {
            System.err.println("RA mode could not be enabled and disabled at the same time");
        }

        boolean ra = isEnabled(era, dra, false);

        CAHasRequestorEntry entry = new CAHasRequestorEntry(requestorName);
        entry.setRa(ra);
        entry.setProfiles(profiles);
        Set<Permission> _permissions = new HashSet<Permission>();
        for(String permission : permissions)
        {
            Permission _permission = Permission.getPermission(permission);
            if(_permission == null)
            {
                throw new ConfigurationException("Invalid permission: " + permission);
            }
            _permissions.add(_permission);
        }
        entry.setPermissions(_permissions);

        caManager.addCmpRequestorToCA(entry, caName);

        return null;
    }
}
