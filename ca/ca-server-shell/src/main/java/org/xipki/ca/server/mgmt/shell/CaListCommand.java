/*
 * Copyright (c) 2014 xipki.org
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

import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.CAEntry;

@Command(scope = "ca", name = "ca-list", description="List CAs")
public class CaListCommand extends CaCommand
{
    @Option(name = "-name",
            description = "CA name",
            required = false)
    protected String           caName;

    @Option(name = "-v", aliases="--verbose",
            required = false, description = "Show CA information verbosely")
    protected Boolean          verbose;

    @Override
    protected Object doExecute()
    throws Exception
    {
        StringBuilder sb = new StringBuilder();

        if(caName == null)
        {
            Set<String> names = caManager.getCANames();
            int n = names.size();

            sb.append(n + " CAs are configured:\n");
            for(String paramName : names)
            {
                sb.append("\t").append(paramName);
                String alias = caManager.getAliasName(paramName);
                if(alias != null)
                {
                    sb.append(" (alias: ").append(alias).append(")");
                }
                sb.append("\n");
            }
        }
        else
        {
            CAEntry entry = caManager.getCA(caName);
            if(entry == null)
            {
                sb.append("Could not find CA '" + caName + "'");
            }
            else
            {
                sb.append(entry.toString(verbose == null ? false : verbose.booleanValue()));
            }
        }

        System.out.println(sb.toString());

        return null;
    }
}
