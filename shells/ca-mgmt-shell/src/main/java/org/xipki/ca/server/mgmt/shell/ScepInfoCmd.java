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

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.ca.server.mgmt.shell.completer.ScepNameCompleter;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "scep-info",
        description = "show information of SCEP")
@Service
public class ScepInfoCmd extends CaAction {

    @Argument(index = 0, name = "name", description = "SCEP name")
    @Completion(ScepNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v",
            description = "show CA information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
        StringBuilder sb = new StringBuilder();
        if (name == null) {
            sb.append("SCEPs: ");
            sb.append(caManager.getScepNames());
            println(sb.toString());
        } else {
            ScepEntry scep = caManager.getScepEntry(name);
            if (scep == null) {
                throw new CmdFailure("could not find SCEP '" + name + "'");
            }
            System.out.println(scep.toString(verbose.booleanValue()));
        }

        return null;
    } // method execute0

}
