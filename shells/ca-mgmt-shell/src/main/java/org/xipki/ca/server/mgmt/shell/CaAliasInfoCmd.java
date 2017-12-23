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
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.completer.CaAliasCompleter;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "caalias-info",
        description = "show information of CA alias")
@Service
public class CaAliasInfoCmd extends CaAction {

    @Argument(index = 0, name = "alias", description = "CA alias")
    @Completion(CaAliasCompleter.class)
    private String caAlias;

    @Override
    protected Object execute0() throws Exception {
        Set<String> aliasNames = caManager.getCaAliasNames();

        StringBuilder sb = new StringBuilder();

        if (caAlias == null) {
            int size = aliasNames.size();

            if (size == 0 || size == 1) {
                sb.append((size == 0) ? "no" : "1");
                sb.append(" CA alias is configured\n");
            } else {
                sb.append(size).append(" CA aliases are configured:\n");
            }

            List<String> sorted = new ArrayList<>(aliasNames);
            Collections.sort(sorted);

            for (String aliasName : sorted) {
                sb.append("\t").append(aliasName).append("\n");
            }
        } else {
            if (aliasNames.contains(caAlias)) {
                String paramValue = caManager.getCaNameForAlias(caAlias);
                sb.append(caAlias).append("\n\t").append(paramValue);
            } else {
                throw new CmdFailure("could not find CA alias '" + caAlias + "'");
            }
        }

        println(sb.toString());
        return null;
    } // method execute0

}
