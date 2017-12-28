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
import org.xipki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.PermissionCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNameAndAllCompleter;
import org.xipki.ca.server.mgmt.shell.completer.RequestorNameCompleter;
import org.xipki.console.karaf.completer.YesNoCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "careq-add",
        description = "add requestor to CA")
@Service
public class CaRequestorAddCmd extends CaAction {

    @Option(name = "--ca", required = true,
            description = "CA name\n(required)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--requestor", required = true,
            description = "requestor name\n(required)")
    @Completion(RequestorNameCompleter.class)
    private String requestorName;

    @Option(name = "--ra",
            description = "whether as RA")
    @Completion(YesNoCompleter.class)
    private String raS = "no";

    @Option(name = "--permission", required = true, multiValued = true,
            description = "permission\n(required, multi-valued)")
    @Completion(PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--profile", multiValued = true,
            description = "profile name or 'ALL' for all profiles\n(multi-valued)")
    @Completion(ProfileNameAndAllCompleter.class)
    private Set<String> profiles;

    @Override
    protected Object execute0() throws Exception {
        boolean ra = isEnabled(raS, false, "ra");

        CaHasRequestorEntry entry = new CaHasRequestorEntry(new NameId(null, requestorName));
        entry.setRa(ra);
        entry.setProfiles(profiles);
        int intPermission = ShellUtil.getPermission(permissions);
        entry.setPermission(intPermission);

        boolean bo = caManager.addRequestorToCa(entry, caName);
        output(bo, "added", "could not add", "requestor " + requestorName + " to CA " + caName);
        return null;
    }

}
