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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.ca.server.mgmt.shell.completer.RequestorNameCompleter;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "requestor-info",
        description = "show information of requestor")
@Service
public class RequestorInfoCmd extends CaAction {

    @Argument(index = 0, name = "name", description = "requestor name")
    @Completion(RequestorNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v",
            description = "show requestor information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
        StringBuilder sb = new StringBuilder();

        if (name == null) {
            Set<String> names = caManager.getRequestorNames();
            int size = names.size();

            if (size == 0 || size == 1) {
                sb.append((size == 0) ? "no" : "1");
                sb.append(" CMP requestor is configured\n");
            } else {
                sb.append(size).append(" CMP requestors are configured:\n");
            }

            List<String> sorted = new ArrayList<>(names);
            Collections.sort(sorted);

            for (String entry : sorted) {
                sb.append("\t").append(entry).append("\n");
            }
        } else {
            CmpRequestorEntry entry = caManager.getRequestor(name);
            if (entry == null) {
                throw new CmdFailure("could not find CMP requestor '" + name + "'");
            } else {
                sb.append(entry.toString(verbose.booleanValue()));
            }
        }

        println(sb.toString());
        return null;
    } // method execute0

}
