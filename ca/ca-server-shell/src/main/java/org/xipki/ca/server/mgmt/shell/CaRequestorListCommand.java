/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "careq-list", description="List requestors in CA")
public class CaRequestorListCommand extends CaCommand
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

        Set<CAHasRequestorEntry> entries = caManager.getCmpRequestorsForCA(caName);
        if(entries != null && entries.isEmpty() == false)
        {
            sb.append("Requestors trusted by CA " + caName).append("\n");
            for(CAHasRequestorEntry entry  : entries)
            {
                sb.append("\t").append(entry).append("\n");
            }
        }
        else
        {
            sb.append("\tNo requestor for CA " + caName + " is configured");
        }
        System.out.println(sb.toString());

        return null;
    }
}
