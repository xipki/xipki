/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.PKIStatusInfo;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "remove-cert", description="Remove certificate")
public class RemoveCertCommand extends UnRevRemoveCertCommand
{

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(certFile == null && (caCertFile == null || serialNumber == null))
        {
            err("either cert or (cacert, serial) must be specified");
            return null;
        }

        CertIDOrError certIdOrError;
        if(certFile != null)
        {
            X509Certificate cert = IoCertUtil.parseCert(certFile);
            certIdOrError = raWorker.removeCert(cert);
        }
        else
        {
            X509Certificate caCert = IoCertUtil.parseCert(caCertFile);
            X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
            certIdOrError = raWorker.removeCert(issuer, new BigInteger(serialNumber));
        }

        if(certIdOrError.getError() != null)
        {
            PKIStatusInfo error = certIdOrError.getError();
            err("Removing certificate failed: " + error);
        }
        else
        {
            out("Removed certificate");
        }
        return null;
    }

}
