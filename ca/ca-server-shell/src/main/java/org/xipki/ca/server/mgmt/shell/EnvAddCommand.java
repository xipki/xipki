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

@Command(scope = "ca", name = "env-add", description="Add environment parameter")
public class EnvAddCommand extends CaCommand
{

    @Option(name = "-name",
            description = "Required. Parameter Name",
            required = true, multiValued = false)
    protected String            name;

    @Option(name = "-value",
            description = "Required. Environment paremter value",
            required = true)
    protected String            value;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.addEnvParam(name, value);
        return null;
    }
}
