/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.HashSet;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.security.common.ConfigurationException;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "careq-add", description="Add requestor to CA")
public class CaRequestorAddCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name",
            required = true)
    protected String caName;

    @Option(name = "-requestor",
            required = true, description = "Required. Requestor name")
    protected String requestorName;

    @Option(name = "-ra",
            description = "Whether as RA.\n"
                    + "Valid values are 'yes' and 'no'")
    protected String raS = "no";

    @Option(name = "-permission",
            description = "Required. Permission, multi options is allowed. allowed values are\n"
                    + permissionsText,
            required = true, multiValued = true)
    protected Set<String> permissions;

    @Option(name = "-profile",
            description = "Required. Profile name or 'all' for all profiles, multi options is allowed",
            required = true, multiValued = true)
    protected Set<String> profiles;

    @Override
    protected Object doExecute()
    throws Exception
    {
        boolean ra = isEnabled(raS, false, "ra");

        CAHasRequestorEntry entry = new CAHasRequestorEntry(requestorName);
        entry.setRa(ra);
        entry.setProfiles(profiles);
        Set<Permission> _permissions = new HashSet<>();
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
        out("added requestor " + requestorName + " to CA " + caName);

        return null;
    }
}
