/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.felix.gogo.commands.Argument;
import org.apache.felix.gogo.commands.Command;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "env-list", description="List environment parameters")
public class EnvListCommand extends CaCommand
{
    @Argument(index = 0, name = "name", description = "Environment parameter name", required = false)
    protected String name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        StringBuilder sb = new StringBuilder();

        if(name == null)
        {
            Set<String> paramNames = caManager.getEnvParamNames();
            int n = paramNames.size();

            if(n == 0 || n == 1)
            {
                sb.append(((n == 0) ? "no" : "1") + " environment parameter is configured\n");
            }
            else
            {
                sb.append(n + " enviroment paramters are configured:\n");
            }

            List<String> sorted = new ArrayList<>(paramNames);
            Collections.sort(sorted);

            for(String paramName : sorted)
            {
                sb.append("\t").append(paramName).append("\n");
            }
        }
        else
        {
            String paramValue = caManager.getEnvParam(name);
            sb.append(name).append("\n\t").append(paramValue);
        }

        out(sb.toString());

        return null;
    }
}
