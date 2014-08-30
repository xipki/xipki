/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "responder-rm", description="Remove responder")
public class ResponderRemoveCommand extends CaCommand
{
    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCmpResponder();
        out("removed CMP responder");
        return null;
    }
}
