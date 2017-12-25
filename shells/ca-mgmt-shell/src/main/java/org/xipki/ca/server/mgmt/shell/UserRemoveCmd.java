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

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "user-rm",
        description = "remove user")
@Service
public class UserRemoveCmd extends CaAction {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "user Name\n"
                    + "(required)")
    private String name;

    @Override
    protected Object execute0() throws Exception {
        boolean bo = caManager.removeUser(name);
        output(bo, "removed", "could not remove", "user " + name);
        return null;
    }

}
