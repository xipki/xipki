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

import java.util.List;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;

@Command(scope = "ca", name = "caprofile-add", description="Add profile to CA")
public class CaProfileAddCommand extends CaCommand
{
    @Option(name = "-ca",
            description = " Required. CA name",
            required = true)
    protected String           caName;

    @Option(name = "-profile",
        description = "Required. Profile profileNames, multi values allowed",
        required = true, multiValued = true)
    protected List<String>            profileNames;

    @Override
    protected Object doExecute()
    throws Exception
    {
        for(String name : profileNames)
        {
            caManager.addCertProfileToCA(name, caName);
        }
        return null;
    }
}
