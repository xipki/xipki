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

@Command(scope = "caclient", name = "gencrl", description="Generate CRL")
public class GenCRLCommand extends CRLCommand
{
    @Override
    protected X509CRL retrieveCRL(String caName)
    throws RAWorkerException, PKIErrorException
    {
        return raWorker.generateCRL(caName);
    }

}
