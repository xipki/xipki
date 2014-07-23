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

@Command(scope = "ca", name = "clear-publishqueue", description="Clear publish queue")
public class ClearPublishQueueCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name or 'all' for all CAs",
            required = true)
    protected String           caName;

    @Option(name = "-publisher",
        required = true, multiValued = true,
        description = "Required. Publisher name or 'all' for all publishers. Multivalued")
    protected List<String>     publisherNames;

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

        caManager.clearPublishQueue(caName, publisherNames);
        return null;
    }
}
