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

@Command(scope = "keytool", name = "ec", description="Generate EC keypair in PKCS#11 device")
public class P11ECKeyGenCommand extends P11KeyGenCommand
{
    @Option(name = "-curve",
            description = "EC Curve name",
            required = false)
    protected String curveName = "brainpoolp256r1";

    @Override
    protected Object doExecute()
    throws Exception
    {
        P11KeypairGenerator gen = new P11KeypairGenerator(securityFactory);
        P11KeypairGenerationResult keyAndCert = gen.generateECDSAKeypairAndCert(
                moduleName, getSlotId(),
                curveName, label, getSubject(),
                getKeyUsage(), getExtendedKeyUsage());
        saveKeyAndCert(keyAndCert);
        return null;
    }

}
