/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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

package org.xipki.ca.server.mgmt.shell;

import java.util.HashSet;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.PermissionCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNamePlusAllCompleter;
import org.xipki.ca.server.mgmt.shell.completer.RequestorNameCompleter;
import org.xipki.console.karaf.YesNoCompleter;
import org.xipki.security.common.ConfigurationException;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "careq-add", description="Add requestor to CA")
@Service
public class CaRequestorAddCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name",
            required = true)
    @Completion(CaNameCompleter.class)
    protected String caName;

    @Option(name = "-requestor",
            required = true, description = "Required. Requestor name")
    @Completion(RequestorNameCompleter.class)
    protected String requestorName;

    @Option(name = "-ra",
            description = "Whether as RA.\n"
                    + "Valid values are 'yes' and 'no'")
    @Completion(YesNoCompleter.class)
    protected String raS = "no";

    @Option(name = "-permission",
            description = "Required. Permission, multi options is allowed. allowed values are\n"
                    + permissionsText,
            required = true, multiValued = true)
    @Completion(PermissionCompleter.class)
    protected Set<String> permissions;

    @Option(name = "-profile",
            description = "Required. Profile name or 'all' for all profiles, multi options is allowed",
            required = true, multiValued = true)
    @Completion(ProfileNamePlusAllCompleter.class)
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
