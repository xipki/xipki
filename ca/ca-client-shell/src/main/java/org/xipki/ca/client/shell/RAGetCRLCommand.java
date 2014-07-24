/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import java.security.cert.X509CRL;

import org.apache.felix.gogo.commands.Command;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "getcrl", description="Download CRL")
public class RAGetCRLCommand extends RACRLCommand
{

    @Override
    protected X509CRL retrieveCRL(String caName)
    throws RAWorkerException, PKIErrorException
    {
        return raWorker.downloadCRL(caName);
    }

}
