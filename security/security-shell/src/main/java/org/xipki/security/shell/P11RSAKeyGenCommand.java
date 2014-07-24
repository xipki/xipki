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
import org.xipki.security.api.P11KeypairGenerationResult;
import org.xipki.security.p11.iaik.P11KeypairGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "rsa", description="Generate RSA keypair in PKCS#11 device")
public class P11RSAKeyGenCommand extends P11KeyGenCommand
{
    @Option(name = "-keysize",
            description = "Keysize in bit, the default is 2048",
            required = false)
    protected Integer keysize;

    @Option(name = "-e",
            description = "public exponent, the default is 65537",
            required = false)
    protected String publicExponent;

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

        BigInteger _publicExponent;
        if(publicExponent == null)
        {
            _publicExponent = BigInteger.valueOf(65537);
        }
        else
        {
            _publicExponent = new BigInteger(publicExponent);
        }

        P11KeypairGenerator gen = new P11KeypairGenerator();

        P11KeypairGenerationResult keyAndCert = gen.generateRSAKeypairAndCert(
                securityFactory.getPkcs11Module(), getSlotId(), getPassword(),
                keysize, _publicExponent,
                label, getSubject(),
                getKeyUsage(),
                getExtendedKeyUsage());
        saveKeyAndCert(keyAndCert);

        return null;
    }

}
