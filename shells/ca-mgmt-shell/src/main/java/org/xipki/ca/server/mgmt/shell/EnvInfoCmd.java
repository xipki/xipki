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
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "env-info",
        description = "show information of CA environment parameter")
@Service
public class EnvInfoCmd extends CaAction {

    @Argument(index = 0, name = "name", description = "environment parameter name")
    private String name;

    @Override
    protected Object execute0() throws Exception {
        StringBuilder sb = new StringBuilder();

        if (name == null) {
            Set<String> paramNames = caManager.getEnvParamNames();
            int size = paramNames.size();

            if (size == 0 || size == 1) {
                sb.append((size == 0) ? "no" : "1");
                sb.append(" environment parameter is configured\n");
            } else {
                sb.append(size).append(" environment parameters are configured:\n");
            }

            List<String> sorted = new ArrayList<>(paramNames);
            Collections.sort(sorted);

            for (String paramName : sorted) {
                sb.append("\t").append(paramName).append("\n");
            }
        } else {
            String paramValue = caManager.getEnvParam(name);
            if (paramValue == null) {
                throw new CmdFailure("\tno environment named '" + name + " is configured");
            } else {
                sb.append(name).append("\n\t").append(paramValue);
            }
        }

        println(sb.toString());
        return null;
    } // method execute0

}
