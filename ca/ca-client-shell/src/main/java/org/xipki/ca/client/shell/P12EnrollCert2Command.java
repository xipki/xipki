/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "enroll2-p12", description="Enroll certificate as non-RA (PKCS#12 keystore)")
public class P12EnrollCert2Command extends EnrollCert2Command
{
    @Option(name = "-p12",
            required = true, description = "Required. PKCS#12 request file")
    protected String p12File;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#12 file")
    protected String password;

    @Override
    protected ConcurrentContentSigner getSigner()
    throws SignerException
    {
        if(password == null)
        {
            password = new String(readPassword());
        }

        String signerConfWithoutAlgo = SecurityFactoryImpl.getKeystoreSignerConfWithoutAlgo(p12File, password, 1);
        return securityFactory.createSigner("PKCS12", signerConfWithoutAlgo, hashAlgo, false, (X509Certificate[]) null);
    }

}
