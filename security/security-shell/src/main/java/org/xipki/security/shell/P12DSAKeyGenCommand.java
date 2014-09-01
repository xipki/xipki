/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.P12KeypairGenerationResult;
import org.xipki.security.p10.P12KeypairGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "rsa-p12", description="Generate RSA keypair in PKCS#12 keystore")
public class P12DSAKeyGenCommand extends P12KeyGenCommand
{
    @Option(name = "-plen",
            description = "Bit length of the prime",
            required = false)
    protected Integer pLen = 2048;

    @Option(name = "-qlen",
            description = "Bit length of the sub-prime",
            required = false)
    protected Integer qLen;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(pLen % 1024 != 0)
        {
            err("plen is not multiple of 1024: " + pLen);
            return null;
        }

        if(qLen == null)
        {
            if(pLen >= 2048)
            {
                qLen = 256;
            }
            else
            {
                qLen = 160;
            }
        }

        P12KeypairGenerator gen = new P12KeypairGenerator.DSAIdentityGenerator(
                pLen, qLen, getPassword(), subject,
                getKeyUsage(), getExtendedKeyUsage());

        P12KeypairGenerationResult keyAndCert = gen.generateIdentity();
        saveKeyAndCert(keyAndCert);

        return null;
    }

}
