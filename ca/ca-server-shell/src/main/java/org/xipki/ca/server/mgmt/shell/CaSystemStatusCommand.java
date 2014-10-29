/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.xipki.ca.common.CASystemStatus;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "system-status", description="Show CA system status")
public class CaSystemStatusCommand extends CaCommand
{
    @Override
    protected Object doExecute()
    throws Exception
    {
        CASystemStatus status = caManager.getCASystemStatus();
        if(status != null)
        {
            out(status.toString());
        }
        else
        {
            err("status is NULL");
        }
        return null;
    }
}
