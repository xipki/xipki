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

@Command(scope = "ca", name = "caprofile-rm", description="Remove certificate profile from CA")
public class CaProfileRemoveCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name",
            required = true)
    protected String           caName;

    @Option(name = "-profile",
            required = true, description = "Required. Certificate profile name")
    protected String            profileName;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCertProfileFromCA(profileName, caName);
        return null;
    }
}
