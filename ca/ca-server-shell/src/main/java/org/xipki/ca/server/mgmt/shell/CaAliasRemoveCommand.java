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

@Command(scope = "ca", name = "caalias-rm", description="Remove CA alias")
public class CaAliasRemoveCommand extends CaCommand
{
    @Option(name = "-alias",
            description = "Required. CA alias",
            required = true)
    protected String            caAlias;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCaAlias(caAlias);
        return null;
    }
}
