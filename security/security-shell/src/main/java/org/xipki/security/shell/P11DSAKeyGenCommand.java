/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.p11.P11KeypairGenerationResult;
import org.xipki.security.p11.iaik.P11KeypairGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "dsa", description="Generate DSA keypair in PKCS#11 device")
public class P11DSAKeyGenCommand extends P11KeyGenCommand
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

        P11KeypairGenerator gen = new P11KeypairGenerator(securityFactory);

        P11KeypairGenerationResult keyAndCert = gen.generateDSAKeypairAndCert(
                moduleName, getSlotId(),
                pLen, qLen,
                label, getSubject(),
                getKeyUsage(),
                getExtendedKeyUsage());
        saveKeyAndCert(keyAndCert);

        return null;
    }

}
