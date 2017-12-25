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
import org.xipki.ca.server.mgmt.api.AddUserEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "user-add",
        description = "add user")
@Service
public class UserAddCmd extends CaAction {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "user Name\n"
                    + "(required)")
    private String name;

    @Option(name = "--password",
            description = "user password")
    private String password;

    @Option(name = "--inactive",
            description = "do not activate this user")
    private Boolean inactive = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
        if (password == null) {
            password = new String(readPassword());
        }
        AddUserEntry userEntry = new AddUserEntry(new NameId(null, name), !inactive, password);
        boolean bo = caManager.addUser(userEntry);
        output(bo, "added", "could not add", "user " + name);
        return null;
    }

}
