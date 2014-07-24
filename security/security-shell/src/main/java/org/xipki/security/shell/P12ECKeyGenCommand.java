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
import org.xipki.security.p10.P12KeypairGenerator.ECDSAIdentityGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "ec-p12", description="Generate EC keypair in PKCS#12 keystore")
public class P12ECKeyGenCommand extends P12KeyGenCommand
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

        ECDSAIdentityGenerator gen = new P12KeypairGenerator.ECDSAIdentityGenerator(
                curveName, getPassword(), subject, getKeyUsage(), getExtendedKeyUsage());

        P12KeypairGenerationResult keyAndCert = gen.generateIdentity();
        saveKeyAndCert(keyAndCert);

        return null;
    }

}
