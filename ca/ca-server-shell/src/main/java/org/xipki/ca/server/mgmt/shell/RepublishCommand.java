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

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "republish", description="Republish certificates")
public class RepublishCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name or 'all' for all CAs",
            required = true)
    protected String caName;

    @Option(name = "-publisher",
        required = true, multiValued = true,
        description = "Required. Publisher name or 'all' for all publishers. Multivalued")
    protected List<String> publisherNames;

    @Override
    protected Object doExecute()
    throws Exception
    {
        boolean allPublishers = false;
        for(String publisherName : publisherNames)
        {
            if("all".equalsIgnoreCase(publisherName))
            {
                allPublishers = true;
                break;
            }
        }

        if(allPublishers)
        {
            publisherNames = null;
        }

        if("all".equalsIgnoreCase(caName))
        {
            caName = null;
        }

        boolean successfull = caManager.republishCertificates(caName, publisherNames);
        if(successfull)
        {
            System.out.println("Replubished certificates");
        }
        else
        {
            System.err.println("Replubishing certificates failed");
        }
        return null;
    }
}
