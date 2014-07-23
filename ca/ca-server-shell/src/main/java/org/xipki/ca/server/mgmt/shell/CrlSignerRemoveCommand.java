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

@Command(scope = "ca", name = "crlsigner-rm", description="Remove CRL signer")
public class CrlSignerRemoveCommand extends CaCommand
{

    @Option(name = "-name",
            description = "Required. CRL signer name",
            required = true, multiValued = false)
    protected String            name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCrlSigner(name);
        return null;
    }
}
