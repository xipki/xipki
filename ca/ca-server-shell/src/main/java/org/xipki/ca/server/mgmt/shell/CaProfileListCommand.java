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

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "caprofile-list", description="List certificate profiles in given CA")
public class CaProfileListCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name",
            required = true)
    protected String caName;

    @Override
    protected Object doExecute()
    throws Exception
    {
        StringBuilder sb = new StringBuilder();
        if(caManager.getCA(caName) == null)
        {
            sb.append("Could not find CA '" + caName + "'");
        }
        else
        {
            Set<String> entries = caManager.getCertProfilesForCA(caName);
            if(entries != null && entries.isEmpty() == false)
            {
                sb.append("Certificate Profiles supported by CA " + caName).append("\n");

                List<String> sorted = new ArrayList<>(entries);
                Collections.sort(sorted);

                for(String entry  : sorted)
                {
                    sb.append("\t").append(entry).append("\n");
                }
            }
            else
            {
                sb.append("\tNo profile for CA " + caName + " is configured");
            }
        }

        out(sb.toString());

        return null;
    }
}
