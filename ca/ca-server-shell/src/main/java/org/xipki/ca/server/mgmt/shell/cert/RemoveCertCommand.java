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
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.X509CA;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "remove-cert", description="Remove certificate")
public class RemoveCertCommand extends CaCertCommand
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
        X509CA ca = caManager.getX509CA(caName);
        if(ca == null)
        {
            System.err.println("CA " + caName + " not available");
            return null;
        }

        X509CertificateWithMetaInfo cert =
                ca.removeCertificate(BigInteger.valueOf(serialNumber));

        if(cert != null)
        {
            System.out.println("Removed certificate");
        }
        else
        {
            System.out.println("Could not remove certificate");
        }

        return null;
    }

}
