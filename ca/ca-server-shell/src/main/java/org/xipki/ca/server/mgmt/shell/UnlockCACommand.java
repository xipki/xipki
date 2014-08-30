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

@Command(scope = "ca", name = "unlock", description="Unlock the CA syste")
public class UnlockCACommand extends CaCommand
{
    @Override
    protected Object doExecute()
    throws Exception
    {
        boolean unlocked = caManager.unlockCA();

        if(unlocked)
        {
            out("Unlocked CA system, calling ca:ca-restart to restart CA system");
        }
        else
        {
            err("Could not unlock CA system");
        }
        out("unlocked CMP responder");
        return null;
    }
}
