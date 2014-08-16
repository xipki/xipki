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
import org.xipki.ca.server.mgmt.api.CrlSignerEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "crlsigner-list", description="List CRL signers")
public class CrlSignerListCommand extends CaCommand
{
    @Argument(index = 0, name = "name", description = "CRL signer name", required = false)
    protected String name;

    @Option(name = "-v", aliases="--verbose",
            required = false, description = "Show CRL signer information verbosely")
    protected Boolean verbose;

    @Override
    protected Object doExecute()
    throws Exception
    {
        StringBuilder sb = new StringBuilder();

        if(name == null)
        {
            Set<String> names = caManager.getCrlSignerNames();
            int n = names.size();

            if(n == 0 || n == 1)
            {
                sb.append(((n == 0) ? "no" : "1") + " CRL signer is configured\n");
            }
            else
            {
                sb.append(n + " CRL signers are configured:\n");
            }

            List<String> sorted = new ArrayList<>(names);
            Collections.sort(sorted);

            for(String name : sorted)
            {
                sb.append("\t").append(name).append("\n");
            }
        }
        else
        {
            CrlSignerEntry entry = caManager.getCrlSigner(name);
            if(entry != null)
            {
                sb.append(entry.toString(verbose == null ? false :verbose.booleanValue()));
            }
        }

        System.out.println(sb.toString());

        return null;
    }
}
