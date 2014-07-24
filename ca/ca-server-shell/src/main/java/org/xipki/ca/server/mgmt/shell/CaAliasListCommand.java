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

@Command(scope = "ca", name = "caalias-list", description="List CA aliases")
public class CaAliasListCommand extends CaCommand
{
    @Argument(index = 0, name = "alias", description = "CA alias", required = false)
    protected String caAlias;

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

            List<String> sorted = new ArrayList<>(aliasNames);
            Collections.sort(sorted);

            for(String aliasName : sorted)
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
