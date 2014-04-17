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

import java.util.HashSet;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;

@Command(scope = "ca", name = "ca-restart", description="Restart CA system")
public class CaRestartCommand extends CaCommand
{

    @Override
    protected Object doExecute() throws Exception
    {
        boolean successfull = caManager.restartCaSystem();
        if(successfull == false)
        {
            System.err.println("Could not restart CA system");
            return null;
        }

        StringBuilder sb = new StringBuilder("Restarted CAs");
        Set<String> names = new HashSet<String>(caManager.getCANames());

        if(names.size() > 0)
        {
            sb.append(" with following CAs: ");
            Set<String> caAliasNames = caManager.getCaAliasNames();
             for(String aliasName : caAliasNames)
            {
                 String name = caManager.getCaName(aliasName);
                 names.remove(name);

                sb.append(name).append(" (alias ").append(aliasName).append(")").append(", ");
            }

             for(String name : names)
             {
                sb.append(name).append(", ");
             }

             int len = sb.length();
             sb.delete(len-2, len);
        }
        else
        {
            sb.append(": no CA is configured");
        }

        System.out.println(sb);
        return null;
    }
}
