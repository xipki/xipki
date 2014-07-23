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

@Command(scope = "ca", name = "env-rm", description="Remove environment parameter")
public class EnvRemoveCommand extends CaCommand
{

    @Option(name = "-name",
            description = "Required. Parameter Name",
            required = true, multiValued = false)
    protected String            name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeEnvParam(name);
        return null;
    }
}
