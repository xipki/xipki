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

@Command(scope = "ca", name = "ca-unrevoke", description="Unrevoke CA")
public class CaUnrevokeCommand extends CaCommand
{
    @Option(name = "-name",
            description = "Required, CA name",
            required = true)
    protected String           caName;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(caManager.getCANames().contains(caName) == false)
        {
            System.out.println("invalid CA name " + caName);
            return null;
        }

        caManager.unrevokeCa(caName);

        return null;
    }
}
