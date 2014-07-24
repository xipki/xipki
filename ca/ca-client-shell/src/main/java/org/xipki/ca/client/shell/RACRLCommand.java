/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import java.io.File;
import java.security.cert.X509CRL;
import java.util.Set;

import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;

/**
 * @author Lijun Liao
 */

public abstract class RACRLCommand extends ClientCommand
{

    @Option(name = "-ca",
            required = false, description = "Required if multiple CAs are configured. CA name")
    protected String caName;

    @Option(name = "-out",
            description = "Required. Where to save the CRL",
            required = true)
    protected String outFile;

    protected abstract X509CRL retrieveCRL(String caName)
    throws RAWorkerException, PKIErrorException;

    @Override
    protected Object doExecute()
    throws Exception
    {
        Set<String> caNames = raWorker.getCaNames();
        if(caNames.isEmpty())
        {
            System.out.println("No CA is configured");
            return  null;
        }

        if(caName != null && ! caNames.contains(caName))
        {
            System.err.println("CA " + caName + " is not within the configured CAs " + caNames);
            return null;
        }

        if(caName == null)
        {
            if(caNames.size() == 1)
            {
                caName = caNames.iterator().next();
            }
            else
            {
                System.err.println("No caname is specified, one of " + caNames + " is required");
                return null;
            }
        }

        X509CRL crl = retrieveCRL(caName);
        if(crl == null)
        {
            System.err.println("Received no CRL from server");
            return null;
        }

        saveVerbose("Saved CRL to file", new File(outFile), crl.getEncoded());
        return null;
    }

}
