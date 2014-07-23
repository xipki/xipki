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

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.common.EnvironmentParameterResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "env-list", description="List environment parameters")
public class EnvListCommand extends CaCommand
{

    @Option(name = "-name",
            description = "Parameter Name",
            required = false, multiValued = false)
    protected String name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        EnvironmentParameterResolver envParameterResolver = caManager.getEnvParameterResolver();

        StringBuilder sb = new StringBuilder();

        if(name == null)
        {
            Set<String> paramNames = envParameterResolver.getAllParameterNames();
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
            String paramValue = envParameterResolver.getParameterValue(name);
            sb.append(name).append("\n\t").append(paramValue);
        }

        System.out.println(sb.toString());

        return null;
    }
}
