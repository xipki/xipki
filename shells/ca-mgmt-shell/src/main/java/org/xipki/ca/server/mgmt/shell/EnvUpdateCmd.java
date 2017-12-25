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

@Command(scope = "ca", name = "env-up",
        description = "update CA environment parameter")
@Service
public class EnvUpdateCmd extends CaAction {

    @Option(name = "--name", aliases = "-n",
            required = true,
                description = "parameter name\n"
                    + "(required)")
    protected String name;

    @Option(name = "--value",
            required = true,
            description = "environment parameter value\n"
                    + "(required)")
    protected String value;

    @Override
    protected Object execute0() throws Exception {
        boolean bo = caManager.changeEnvParam(name, value);
        output(bo, "updated", "could not update",
                "the environment " + name + "=" + getRealString(value));
        return null;
    }

}
