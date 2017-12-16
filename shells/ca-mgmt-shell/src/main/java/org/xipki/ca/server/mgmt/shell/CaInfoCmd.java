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

import java.util.Set;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "ca-info",
        description = "show information of CA")
@Service
public class CaInfoCmd extends CaCommandSupport {

    @Argument(index = 0, name = "name", description = "CA name")
    @Completion(CaNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v",
            description = "show CA information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
        StringBuilder sb = new StringBuilder();
        if (name == null) {
            sb.append("successful CAs:\n");
            String prefix = "  ";
            printCaNames(sb, caManager.getSuccessfulCaNames(), prefix);

            sb.append("failed CAs:\n");
            printCaNames(sb, caManager.getFailedCaNames(), prefix);

            sb.append("inactive CAs:\n");
            printCaNames(sb, caManager.getInactiveCaNames(), prefix);
        } else {
            CaEntry entry = caManager.getCa(name);
            if (entry == null) {
                throw new CmdFailure("could not find CA '" + name + "'");
            } else {
                if (CaStatus.ACTIVE == entry.status()) {
                    boolean started = caManager.getSuccessfulCaNames().contains(
                            entry.ident().name());
                    sb.append("started: ").append(started).append("\n");
                }
                Set<String> aliases = caManager.getAliasesForCa(name);
                sb.append("aliases: ").append(toString(aliases)).append("\n");
                sb.append(entry.toString(verbose.booleanValue()));
            }
        }

        println(sb.toString());
        return null;
    } // method execute0

}
