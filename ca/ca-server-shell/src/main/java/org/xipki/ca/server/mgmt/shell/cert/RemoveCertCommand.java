/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.cert;

import java.math.BigInteger;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.shell.CaCommand;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "remove-cert", description="Remove certificate")
public class RemoveCertCommand extends CaCommand
{
    @Option(name = "-ca",
            required = true, description = "Required. CA name")
    protected String caName;

    @Option(name = "-serial",
            required = true,
            description = "Serial number")
    protected Long serialNumber;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(caManager.getCA(caName) == null)
        {
            err("CA " + caName + " not available");
            return null;
        }

        boolean successful =
                caManager.removeCertificate(caName, BigInteger.valueOf(serialNumber));

        if(successful)
        {
            out("Removed certificate");
        }
        else
        {
            err("Could not remove certificate");
        }

        return null;
    }

}
