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
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.api.CAEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "ca-list", description="List CAs")
public class CaListCommand extends CaCommand
{
    @Argument(index = 0, name = "name", description = "CA name", required = false)
    protected String caName;

    @Option(name = "-v", aliases="--verbose",
            required = false, description = "Show CA information verbosely")
    protected Boolean verbose = Boolean.FALSE;

    @Override
    protected Object doExecute()
    throws Exception
    {
        StringBuilder sb = new StringBuilder();

        if(caName == null)
        {
            Set<String> names = caManager.getCANames();
            int n = names.size();
            if(n == 0 || n == 1)
            {
                sb.append(((n == 0) ? "no" : "1") + " CA is configured\n");
            }
            else
            {
                sb.append(n + " CAs are configured:\n");
            }

            List<String> sorted = new ArrayList<>(names);
            Collections.sort(sorted);
            for(String paramName : sorted)
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
                sb.append(entry.toString(verbose.booleanValue()));
            }
        }

        out(sb.toString());

        return null;
    }
}
