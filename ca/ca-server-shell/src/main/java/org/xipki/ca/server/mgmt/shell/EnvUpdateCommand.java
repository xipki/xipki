/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;

@Command(scope = "ca", name = "env-update", description="Update environment parameter")
public class EnvUpdateCommand extends CaCommand {

	@Option(name = "-name",
            	description = "Required. Parameter Name",
	            required = true, multiValued = false)
	protected String            name;
    
	@Option(name = "-value",
	        description = "Required. Environment paremter value",
	        required = true)
	protected String            value;
	

    @Override
    protected Object doExecute() throws Exception {
    	caManager.changeEnvParam(name, value);
    	System.out.println("Update the environment " + name + "=" + getRealString(value));
        return null;
    }
}
