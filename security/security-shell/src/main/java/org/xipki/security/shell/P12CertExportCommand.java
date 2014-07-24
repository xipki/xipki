/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "export-cert-p12", description="Export certificate from PKCS#12 keystore")
public class P12CertExportCommand extends P12SecurityCommand
{
    @Option(name = "-out",
            required = true, description = "Required. Where to save the certificate")
    protected String outFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        KeyStore ks = getKeyStore();

        String keyname = null;
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements())
        {
            String alias = aliases.nextElement();
            if(ks.isKeyEntry(alias))
            {
                keyname = alias;
                break;
            }
        }

        if(keyname == null)
        {
            throw new SignerException("Could not find private key");
        }

        X509Certificate cert = (X509Certificate) ks.getCertificate(keyname);
        saveVerbose("Saved certificate to file", new File(outFile), cert.getEncoded());

        return null;
    }

}
