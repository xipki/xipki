/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.File;

import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.p11.P11KeypairGenerationResult;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public abstract class P11KeyGenCommand extends KeyGenCommand
{

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer slotIndex;

    @Option(name = "-key-label",
            required = true, description = "Required. Label of the PKCS#11 objects")
    protected String label;

    @Option(name = "-subject",
            required = false, description = "Subject in the self-signed certificate")
    protected String subject;

    @Option(name = "-certout",
            required = false, description = "Where to save the self-signed certificate")
    protected String outputFilename;

    @Option(name = "-module",
            required = false, description = "Name of the PKCS#11 module.")
    protected String moduleName = SecurityFactory.DEFAULT_P11MODULE_NAME;

    protected String getSubject()
    {
        if(subject == null || subject.isEmpty())
        {
            return "CN=" + label;
        }
        return subject;
    }

    protected P11SlotIdentifier getSlotId()
    {
        return new P11SlotIdentifier(slotIndex, null);
    }

    protected void saveKeyAndCert(P11KeypairGenerationResult keyAndCert)
    throws Exception
    {
        out("key id: " + Hex.toHexString(keyAndCert.getId()));
        out("key label: " + keyAndCert.getLabel());
        if(outputFilename != null)
        {
            File certFile = new File(outputFilename);
            saveVerbose("Saved self-signed certificate to file", certFile, keyAndCert.getCertificate().getEncoded());
        }

        securityFactory.getP11CryptService(moduleName).refresh();
    }
}
