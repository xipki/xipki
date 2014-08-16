/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.xipki.ca.server.mgmt.api.CmpControlEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "cmpcontrol-list", description="List CMP control")
public class CmpControlListCommand extends CaCommand
{
    @Override
    protected Object doExecute()
    throws Exception
    {
        CmpControlEntry cmpcontrol = caManager.getCmpControl();
        System.out.println(cmpcontrol);
        return null;
    }
}
