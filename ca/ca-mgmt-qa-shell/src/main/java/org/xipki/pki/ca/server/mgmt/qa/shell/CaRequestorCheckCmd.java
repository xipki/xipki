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

package org.xipki.pki.ca.server.mgmt.qa.shell;

import java.rmi.UnexpectedException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.pki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CAManager;
import org.xipki.pki.ca.server.mgmt.api.Permission;
import org.xipki.pki.ca.server.mgmt.shell.CaCmd;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-caqa", name = "careq-check",
        description="check information of requestors in CA (QA)")
public class CaRequestorCheckCmd extends CaCmd
{
    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Option(name = "--requestor",
            required = true,
            description = "requestor name\n"
                    + "(required)")
    private String requestorName;

    @Option(name = "--ra",
            description = "whether as RA")
    private String raS = "no";

    @Option(name = "--permission",
            multiValued = true,
            description = "permission\n"
                    + "(multi-valued)")
    private Set<String> permissions;

    @Option(name = "--profile",
            multiValued = true,
            description = "profile name or 'all' for all profiles\n"
                    + "(multi-valued)")
    private Set<String> profiles;

    @Override
    protected Object _doExecute()
    throws Exception
    {
        out("checking CA requestor CA='" + caName +  "', requestor='" + requestorName + "'");

        if (caManager.getCA(caName) == null)
        {
            throw new UnexpectedException("could not find CA '" + caName + "'");
        }

        Set<CAHasRequestorEntry> entries = caManager.getCmpRequestorsForCA(caName);
        CAHasRequestorEntry entry = null;
        for (CAHasRequestorEntry m : entries)
        {
            if (m.getRequestorName().equals(requestorName))
            {
                entry = m;
                break;
            }
        }

        if (entry == null)
        {
            throw new CmdFailure("CA is not associated with requestor '" + requestorName + "'");
        }

        boolean ra = isEnabled(raS, false, "ra");
        boolean b = entry.isRa();
        if (ra != b)
        {
            throw new UnexpectedException("ra: is '" + b + "', expected '" + ra + "'");
        }

        if (permissions != null)
        {
            Set<Permission> _permissions = new HashSet<>();
            for (String permission : permissions)
            {
                Permission _permission = Permission.getPermission(permission);
                if (_permission == null)
                {
                    throw new IllegalCmdParamException("invalid permission: " + permission);
                }
                _permissions.add(_permission);
            }

            if (_permissions.equals(entry.getPermissions()) == false)
            {
                throw new UnexpectedException("permissions: is '" + entry.getPermissions()
                        + "', but expected '" + _permissions + "'");
            }
        }

        if (profiles != null)
        {
            if (profiles.size() == 1)
            {
                if (CAManager.NULL.equalsIgnoreCase(profiles.iterator().next()))
                {
                    profiles = Collections.emptySet();
                }
            }

            if (profiles.equals(entry.getProfiles()) == false)
            {
                throw new UnexpectedException("profiles: is '" + entry.getProfiles()
                        + "', but expected '" + profiles + "'");
            }
        }

        out("checking CA requestor CA='" + caName +  "', requestor='" + requestorName + "'");
        return null;
    }
}
