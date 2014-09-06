/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.HashSet;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "ca-restart", description="Restart CA system")
public class CaRestartCommand extends CaCommand
{

    @Override
    protected Object doExecute()
    throws Exception
    {
        boolean successfull = caManager.restartCaSystem();
        if(successfull == false)
        {
            err("Could not restart CA system");
            return null;
        }

        StringBuilder sb = new StringBuilder("Restarted CA system");
        Set<String> names = new HashSet<>(caManager.getCaNames());

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

        out(sb.toString());
        return null;
    }
}
