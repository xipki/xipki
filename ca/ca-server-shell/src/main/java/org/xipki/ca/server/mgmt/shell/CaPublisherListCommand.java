/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.List;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.api.PublisherEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "capub-list", description="List publishers in given CA")
public class CaPublisherListCommand extends CaCommand
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

        List<PublisherEntry> entries = caManager.getPublishersForCA(caName);
        if(entries != null && entries.isEmpty() == false)
        {
            sb.append("Publishers for CA " + caName).append("\n");
            for(PublisherEntry entry  : entries)
            {
                sb.append("\t").append(entry.getName()).append("\n");
            }
        }
        else
        {
            sb.append("\tNo publisher for CA " + caName + " is configured");
        }

        out(sb.toString());

        return null;
    }
}
