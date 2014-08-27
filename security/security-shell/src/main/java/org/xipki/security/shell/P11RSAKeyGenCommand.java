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
import org.xipki.security.api.p11.P11KeypairGenerationResult;
import org.xipki.security.p11.iaik.P11KeypairGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "rsa", description="Generate RSA keypair in PKCS#11 device")
public class P11RSAKeyGenCommand extends P11KeyGenCommand
{
    @Option(name = "-keysize",
            description = "Keysize in bit",
            required = false)
    protected Integer keysize = 2048;

    @Option(name = "-e",
            description = "public exponent",
            required = false)
    protected String publicExponent = "65537";

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(keysize % 1024 != 0)
        {
            err("Keysize is not multiple of 1024: " + keysize);
            return null;
        }

        BigInteger _publicExponent = new BigInteger(publicExponent);

        P11KeypairGenerator gen = new P11KeypairGenerator(securityFactory);

        P11KeypairGenerationResult keyAndCert = gen.generateRSAKeypairAndCert(
                moduleName, getSlotId(),
                keysize, _publicExponent,
                label, getSubject(),
                getKeyUsage(),
                getExtendedKeyUsage());
        saveKeyAndCert(keyAndCert);

        return null;
    }

}
