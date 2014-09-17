/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import java.io.File;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "getcrl", description="Download CRL")
public class GetCRLCommand extends CRLCommand
{
    @Option(name = "-with-basecrl",
            required = false, description = "Indicates whether to retrieve the baseCRL if the current CRL is a delta CRL")
    protected Boolean withBaseCRL = Boolean.FALSE;

    @Option(name = "-basecrl-out",
            required = false, description = "Where to save the baseCRL"
                    + "\nThe default is <out>-baseCRL")
    protected String baseCRLOut;

    @Override
    protected X509CRL retrieveCRL(String caName)
    throws RAWorkerException, PKIErrorException
    {
        return raWorker.downloadCRL(caName);
    }

    @Override
    protected Object doExecute()
    throws Exception
    {
        Set<String> caNames = raWorker.getCaNames();
        if(caNames.isEmpty())
        {
            err("No CA is configured");
            return  null;
        }

        if(caName != null && ! caNames.contains(caName))
        {
            err("CA " + caName + " is not within the configured CAs " + caNames);
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
                err("No caname is specified, one of " + caNames + " is required");
                return null;
            }
        }

        X509CRL crl = retrieveCRL(caName);
        if(crl == null)
        {
            err("Received no CRL from server");
            return null;
        }

        saveVerbose("Saved CRL to file", new File(outFile), crl.getEncoded());

        if(withBaseCRL.booleanValue())
        {
            byte[] octetString = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
            if(octetString != null)
            {
                if(baseCRLOut == null)
                {
                    baseCRLOut = outFile + "-baseCRL";
                }

                byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                BigInteger baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
                crl = raWorker.downloadCRL(caName, baseCrlNumber);
                if(crl == null)
                {
                    err("Received no baseCRL from server");
                }
                else
                {
                    saveVerbose("Saved baseCRL to file", new File(baseCRLOut), crl.getEncoded());
                }
            }
        }

        return null;
    }
}
