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

import java.util.Map;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.ca.server.mgmt.api.UserEntry;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "user-info",
        description = "show information of user")
@Service
public class UserInfoCmd extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "user name")
    private String name;

    @Override
    protected Object execute0() throws Exception {
        UserEntry userEntry = caManager.getUser(name);
        if (userEntry == null) {
            throw new CmdFailure("no user named '" + name + "' is configured");
        }

        StringBuilder sb = new StringBuilder();
        sb.append(userEntry);

        Map<String, CaHasUserEntry> caHasUsers = caManager.getCaHasUsers(name);
        for (String ca : caHasUsers.keySet()) {
            CaHasUserEntry entry = caHasUsers.get(ca);
            sb.append("\n----- CA ").append(ca).append("-----");
            sb.append("\nprofiles: ").append(entry.profiles()).append("\n");
            sb.append("\npermission: ").append(entry.permission());
        }
        println(sb.toString());
        return null;
    }

}
