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

@Command(scope = "ca", name = "requestor-rm", description="Remove requestor")
public class RequestorRemoveCommand extends CaCommand
{

    @Option(name = "-name",
                description = "Required. Requestor name",
                required = true, multiValued = false)
    protected String            name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCmpRequestor(name);
        return null;
    }
}
