/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.P11KeypairGenerationResult;
import org.xipki.security.p11.iaik.P11KeypairGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "ec", description="Generate EC keypair in PKCS#11 device")
public class P11ECKeyGenCommand extends P11KeyGenCommand
{
    @Option(name = "-curve",
            description = "EC Curve name, the default is brainpoolp256r1",
            required = false)
    protected String            curveName;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(curveName == null)
        {
            curveName = "brainpoolp256r1";
        }

        P11KeypairGenerator gen = new P11KeypairGenerator();
        P11KeypairGenerationResult keyAndCert = gen.generateECDSAKeypairAndCert(
                securityFactory.getPkcs11Module(), getSlotId(), getPassword(),
                curveName, label, getSubject(),
                getKeyUsage(), getExtendedKeyUsage());
        saveKeyAndCert(keyAndCert);
        return null;
    }

}
