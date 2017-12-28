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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.ChangeUserEntry;
import org.xipki.console.karaf.IllegalCmdParamException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "user-up",
        description = "update user")
@Service
public class UserUpdateCmd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true,
            description = "user Name\n(required)")
    private String name;

    @Option(name = "--active",
            description = "activate this user")
    private Boolean active;

    @Option(name = "--inactive",
            description = "deactivate this user")
    private Boolean inactive;

    @Option(name = "--password",
            description = "user password, 'CONSOLE' to read from console")
    private String password;

    @Override
    protected Object execute0() throws Exception {
        Boolean realActive;
        if (active != null) {
            if (inactive != null) {
                throw new IllegalCmdParamException(
                        "maximal one of --active and --inactive can be set");
            }
            realActive = Boolean.TRUE;
        } else if (inactive != null) {
            realActive = Boolean.FALSE;
        } else {
            realActive = null;
        }

        ChangeUserEntry entry = new ChangeUserEntry(new NameId(null, name));
        if (realActive != null) {
            entry.setActive(realActive);
        }

        if ("CONSOLE".equalsIgnoreCase(password)) {
            password = new String(readPassword());
        }

        if (password != null) {
            entry.setPassword(password);
        }

        boolean bo = caManager.changeUser(entry);
        output(bo, "changed", "could not change", "user " + name);
        return null;
    }

}
