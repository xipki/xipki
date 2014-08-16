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
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.shell.CaCommand;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "unrevoke-cert", description="Unrevoke certificate")
public class UnrevokeCertCommand extends CaCommand
{
    @Option(name = "-ca",
            required = true, description = "Required. CA name")
    protected String caName;

    @Option(name = "-serial",
            required = true,
            description = "Serial number")
    protected Long   serialNumber;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CAEntry ca = caManager.getCA(caName);
        if(ca == null)
        {
            System.err.println("CA " + caName + " not available");
            return null;
        }

        boolean successful = caManager.unrevokeCertificate(caName, BigInteger.valueOf(serialNumber));

        if(successful)
        {
            System.out.println("Unrevoked certificate");
        }
        else
        {
            System.out.println("Could not unrevoke certificate");
        }

        return null;
    }

}
