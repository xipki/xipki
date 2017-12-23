/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "ca", name = "causer-rm",
        description = "remove user from CA")
@Service
public class CaUserRemoveCmd extends CaAction {

    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--user",
            required = true,
            description = "user name\n"
                    + "(required)")
    private String userName;

    @Override
    protected Object execute0() throws Exception {
        boolean bo = caManager.removeUserFromCa(userName, caName);
        output(bo, "removed", "could not remove",
                "user " + userName + " from CA " + caName);
        return null;
    }

}
