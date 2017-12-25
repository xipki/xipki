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

package org.xipki.ca.server.mgmt.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.EnvUpdateCmd;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "env-check",
        description = "check information of CA environment parameters (QA)")
@Service
public class EnvCheckCmd extends EnvUpdateCmd {

    @Override
    protected Object execute0() throws Exception {
        println("checking environment " + name);

        String is = caManager.getEnvParam(name);
        if (!value.equals(is)) {
            throw new CmdFailure("Environment parameter '" + name + "': is '" + is
                    + "', but expected '" + value + "'");
        }

        println(" checked environment " + name);
        return null;
    }

}
