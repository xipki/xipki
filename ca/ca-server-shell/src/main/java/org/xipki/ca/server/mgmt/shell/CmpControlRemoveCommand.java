/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "cmpcontrol-remove", description="Remove CMP control")
public class CmpControlRemoveCommand extends CaCommand
{
    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCmpControl();
        out("removed CMP control");
        return null;
    }
}
