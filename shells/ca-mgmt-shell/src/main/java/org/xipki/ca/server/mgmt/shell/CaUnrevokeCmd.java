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
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.console.karaf.IllegalCmdParamException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "ca-unrevoke",
        description = "unrevoke CA")
@Service
public class CaUnrevokeCmd extends CaAction {

    @Argument(index = 0, name = "name", description = "CA name", required = true)
    @Completion(CaNameCompleter.class)
    private String caName;

    @Override
    protected Object execute0() throws Exception {
        if (!caManager.getCaNames().contains(caName)) {
            throw new IllegalCmdParamException("invalid CA name " + caName);
        }

        boolean bo = caManager.unrevokeCa(caName);
        output(bo, "unrevoked", "could not unrevoke", "CA " + caName);
        return null;
    }

}
