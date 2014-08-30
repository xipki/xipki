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

@Command(scope = "ca", name = "ca-unrevoke", description="Unrevoke CA")
public class CaUnrevokeCommand extends CaCommand
{
    @Argument(index = 0, name="name", description = "CA name", required = true)
    protected String caName;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(caManager.getCANames().contains(caName) == false)
        {
            err("invalid CA name " + caName);
            return null;
        }

        caManager.unrevokeCa(caName);

        out("unrevoked CA " + caName);

        return null;
    }
}
