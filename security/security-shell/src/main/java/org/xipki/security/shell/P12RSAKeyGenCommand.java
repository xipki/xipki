/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.File;
import java.math.BigInteger;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.P12KeypairGenerationResult;
import org.xipki.security.p10.P12KeypairGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "rsa-p12", description="Generate RSA keypair in PKCS#12 keystore")
public class P12RSAKeyGenCommand extends KeyGenCommand
{
    @Option(name = "-keysize",
            description = "Keysize in bit, the default is 2048",
            required = false)
    protected Integer            keysize;

    @Option(name = "-subject",
            required = true, description = "Required. Subject in the self-signed certificate")
    protected String            subject;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#12 file")
    protected String            password;

    @Option(name = "-out",
            required = true, description = "Required. Where to save the key")
    protected String            keyOutFile;

    @Option(name = "-certout",
            required = false, description = "Where to save the self-signed certificate")
    protected String            certOutFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(keysize == null)
        {
            keysize = 2048;
        }
        else if(keysize % 1024 != 0)
        {
            System.err.println("Keysize is not multiple of 1024: " + keysize);
            return null;
        }

        char[] pwd = readPasswordIfNotSet(password);
        P12KeypairGenerator gen = new P12KeypairGenerator.RSAIdentityGenerator(
                keysize, BigInteger.valueOf(0x10001), pwd, subject,
                getKeyUsage(), getExtendedKeyUsage());

        P12KeypairGenerationResult keyAndCert = gen.generateIdentity();

        File p12File = new File(keyOutFile);
        saveVerbose("Saved PKCS#12 keystore to file", p12File, keyAndCert.getKeystore());
        if(certOutFile != null)
        {
            File certFile = new File(certOutFile);
            saveVerbose("Saved self-signed certificate to file",
                    certFile, keyAndCert.getCertificate().getEncoded());
        }

        return null;
    }

}
