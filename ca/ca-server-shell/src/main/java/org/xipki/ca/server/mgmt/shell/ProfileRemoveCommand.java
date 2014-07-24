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

@Command(scope = "ca", name = "profile-rm", description="Remove Profile")
public class ProfileRemoveCommand extends CaCommand
{
    @Argument(index = 0, name = "name", description = "Certificate profile name", required = true)
    protected String            name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCertProfile(name);
        return null;
    }
}
