/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "capub-remove", description="Remove publisher from CA")
public class CaPublisherRemoveCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name",
            required = true)
    protected String caName;

    @Option(name = "-publisher",
            required = true, description = "Publisher name")
    protected String publisherName;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removePublisherFromCA(publisherName, caName);
        out("removed publisher " + publisherName + " from CA " + caName);
        return null;
    }
}
