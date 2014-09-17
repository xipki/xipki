/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "enroll2", description="Enroll certificate as non-RA (PKCS#11 token)")
public class P11EnrollCert2Command extends EnrollCert2Command
{
    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer slotIndex;

    @Option(name = "-key-id",
            required = false, description = "Id of the private key in the PKCS#11 device.\n"
                    + "Either keyId or keyLabel must be specified")
    protected String keyId;

    @Option(name = "-key-label",
            required = false, description = "Label of the private key in the PKCS#11 device.\n"
                    + "Either keyId or keyLabel must be specified")
    protected String keyLabel;

    @Option(name = "-module",
            required = false, description = "Name of the PKCS#11 module.")
    protected String moduleName = SecurityFactory.DEFAULT_P11MODULE_NAME;

    @Override
    protected ConcurrentContentSigner getSigner()
    throws SignerException
    {
        // TODO Auto-generated method stub
        return null;
    }

}
