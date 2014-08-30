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

@Command(scope = "ca", name = "crlsigner-rm", description="Remove CRL signer")
public class CrlSignerRemoveCommand extends CaCommand
{
    @Argument(index = 0, name = "name", description = "CRL signer name", required = true)
    protected String name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCrlSigner(name);
        out("removed CRL signer " + name);
        return null;
    }
}
