/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.common.CASystemStatus;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "system-status", description="Show CA system status")
public class CaSystemStatusCommand extends CaCommand
{
    @Option(name = "-code",
            required = false, description = "Show only the code of CA system status")
    protected Boolean codeOnly;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CASystemStatus status = caManager.getCASystemStatus();
        if(codeOnly != null && codeOnly.booleanValue())
        {
            System.out.println(status.getCode());
        }
        else
        {
            System.out.println(status);
        }
        return null;
    }
}
