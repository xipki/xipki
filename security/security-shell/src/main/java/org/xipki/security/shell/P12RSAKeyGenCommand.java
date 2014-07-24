/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.math.BigInteger;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.P12KeypairGenerationResult;
import org.xipki.security.p10.P12KeypairGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "rsa-p12", description="Generate RSA keypair in PKCS#12 keystore")
public class P12RSAKeyGenCommand extends P12KeyGenCommand
{
    @Option(name = "-keysize",
            description = "Keysize in bit, the default is 2048",
            required = false)
    protected Integer            keysize;

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

        P12KeypairGenerator gen = new P12KeypairGenerator.RSAIdentityGenerator(
                keysize, BigInteger.valueOf(0x10001), getPassword(), subject,
                getKeyUsage(), getExtendedKeyUsage());

        P12KeypairGenerationResult keyAndCert = gen.generateIdentity();
        saveKeyAndCert(keyAndCert);

        return null;
    }

}
