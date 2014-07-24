/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Argument;
import org.apache.felix.gogo.commands.Command;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "requestor-rm", description="Remove requestor")
public class RequestorRemoveCommand extends CaCommand
{
    @Argument(index = 0, name = "name", description = "Requestor name", required = true)
    protected String name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCmpRequestor(name);
        return null;
    }
}
