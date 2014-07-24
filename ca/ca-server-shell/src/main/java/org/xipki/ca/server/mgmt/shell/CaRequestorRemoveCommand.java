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

@Command(scope = "ca", name = "careq-rm", description="Remove requestor in CA")
public class CaRequestorRemoveCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name",
            required = true)
    protected String caName;

    @Option(name = "-requestor",
            required = true, description = "Required. Requestor name")
    protected String            requestorName;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCmpRequestorFromCA(requestorName, caName);
        return null;
    }
}
