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

@Command(scope = "ca", name = "caalias-rm", description="Remove CA alias")
public class CaAliasRemoveCommand extends CaCommand
{
    @Argument(index = 0, name = "alias", description = "CA alias", required = true)
    protected String            caAlias;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCaAlias(caAlias);
        return null;
    }
}
