/*
 * Copyright (c) 2014 Lijun Liao
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

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "caalias-list", description="List CA aliases")
public class CaAliasListCommand extends CaCommand
{
    @Option(name = "-alias",
            description = "CA alias",
            required = false)
    protected String            caAlias;

    @Override
    protected Object doExecute()
    throws Exception
    {
        Set<String> aliasNames = caManager.getCaAliasNames();

        StringBuilder sb = new StringBuilder();

        if(caAlias == null)
        {
            int n = aliasNames.size();

            if(n == 0 || n == 1)
            {
                sb.append(((n == 0) ? "no" : "1") + " CA alias is configured\n");
            }
            else
            {
                sb.append(n + " CA aliases are configured:\n");
            }

            for(String aliasName : aliasNames)
            {
                sb.append("\t").append(aliasName).append("\n");
            }
        }
        else
        {
            if(aliasNames.contains(caAlias))
            {
                String paramValue = caManager.getCaName(caAlias);
                sb.append(caAlias).append("\n\t").append(paramValue);
            }
            else
            {
                sb.append("Could not find CA alias '" + caAlias + "'");
            }
        }

        System.out.println(sb.toString());

        return null;
    }
}
