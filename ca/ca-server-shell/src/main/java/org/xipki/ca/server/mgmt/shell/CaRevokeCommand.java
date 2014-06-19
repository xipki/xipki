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
import org.xipki.ca.server.mgmt.CAEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "ca-revoke", description="Revoke CA")
public class CaRevokeCommand extends CaCommand
{
    @Option(name = "-name",
            description = "CA name",
            required = false)
    protected String           caName;

    @Option(name = "-reason",
            required = true,
            description = "Required. Reason, valid values are \n" +
                    "0: unspecified\n" +
                    "1: keyCompromise\n" +
                    "2: cACompromise\n" +
                    "3: affiliationChanged\n" +
                    "4: superseded\n" +
                    "5: cessationOfOperation\n" +
                    "6: certificateHold\n" +
                    "9: privilegeWithdrawn")
    protected Integer           reason;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(reason != 0 && reason != 1 && reason != 2 && reason != 3 && reason != 4 && reason != 5 && reason != 6 && reason != 9)
        {
            System.err.println("invalid reason " + reason);
            return null;
        }

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
                sb.append(entry);
            }
        }

        System.out.println(sb.toString());

        return null;
    }
}
