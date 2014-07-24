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

@Command(scope = "ca", name = "env-update", description="Update environment parameter")
public class EnvUpdateCommand extends CaCommand
{

    @Option(name = "-name",
                description = "Required. Parameter Name",
                required = true, multiValued = false)
    protected String name;

    @Option(name = "-value",
            description = "Required. Environment paremter value",
            required = true)
    protected String value;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.changeEnvParam(name, value);
        System.out.println("Update the environment " + name + "=" + getRealString(value));
        return null;
    }
}
