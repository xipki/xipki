/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.PermissionCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNameAndAllCompleter;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "ca", name = "causer-add",
        description = "add user to CA")
@Service
public class CaUserAddCmd extends CaAction {

    @Option(name = "--ca", required = true,
            description = "CA name\n(required)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--user", required = true,
            description = "user name\n(required)")
    private String userName;

    @Option(name = "--permission", required = true, multiValued = true,
            description = "permission\n(required, multi-valued)")
    @Completion(PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--profile", required = true, multiValued = true,
            description = "profile name or 'ALL' for all profiles\n(required, multi-valued)")
    @Completion(ProfileNameAndAllCompleter.class)
    private Set<String> profiles;

    @Override
    protected Object execute0() throws Exception {
        CaHasUserEntry entry = new CaHasUserEntry(new NameId(null, userName));
        entry.setProfiles(profiles);
        int intPermission = ShellUtil.getPermission(permissions);
        entry.setPermission(intPermission);

        boolean bo = caManager.addUserToCa(entry, caName);
        output(bo, "added", "could not add", "user " + userName + " to CA " + caName);
        return null;
    }

}
