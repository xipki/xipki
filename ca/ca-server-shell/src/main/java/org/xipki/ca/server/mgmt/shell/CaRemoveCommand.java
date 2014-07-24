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

@Command(scope = "ca", name = "ca-rm", description="Remove CA")
public class CaRemoveCommand extends CaCommand
{
    @Argument(index = 0, name="name", description = "CA name", required = true)
    protected String           name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCA(name);
        return null;
    }
}
