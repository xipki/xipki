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

@Command(scope = "ca", name = "capub-add", description="Add publishers to CA")
public class CaPublisherAddCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name",
            required = true)
    protected String           caName;

    @Option(name = "-publisher",
        required = true, multiValued = true, description = "Required. Publisher name. Multivalued")
    protected List<String>     publisherNames;

    @Override
    protected Object doExecute()
    throws Exception
    {
        for(String publisherName : publisherNames)
        {
            caManager.addPublisherToCA(publisherName, caName);
        }
        return null;
    }
}
