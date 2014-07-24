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
import org.xipki.security.api.P11KeypairGenerationResult;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.p11.iaik.IaikP11CryptService;

/**
 * @author Lijun Liao
 */

public abstract class P11KeyGenCommand extends KeyGenCommand
{

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer           slotIndex;

    @Option(name = "-key-label",
            required = true, description = "Required. Label of the PKCS#11 objects")
    protected String            label;

    @Option(name = "-subject",
            required = false, description = "Subject in the self-signed certificate")
    protected String            subject;

    @Option(name = "-certout",
            required = false, description = "Where to save the self-signed certificate")
    protected String            outputFilename;

    @Option(name = "-p",
            required = false, description = "Read password from console")
    protected Boolean            readFromConsole;

    protected String getSubject()
    {
        if(subject == null || subject.isEmpty())
        {
            return "CN=" + label;
        }
        return subject;
    }

    protected char[] getPassword()
    {
        char[] pwdInChar = readPasswordIfRequired(password, readFromConsole);
        if(pwdInChar != null)
        {
            password = new String(pwdInChar);
        }
        return pwdInChar;
    }

    protected PKCS11SlotIdentifier getSlotId()
    {
        return new PKCS11SlotIdentifier(slotIndex, null);
    }

    protected void saveKeyAndCert(P11KeypairGenerationResult keyAndCert)
    throws Exception
    {
        System.out.println("key id: " + Hex.toHexString(keyAndCert.getId()));
        System.out.println("key label: " + keyAndCert.getLabel());
        if(outputFilename != null)
        {
            File certFile = new File(outputFilename);
            saveVerbose("Saved self-signed certificate to file", certFile, keyAndCert.getCertificate().getEncoded());
        }

        IaikP11CryptService.getInstance(securityFactory.getPkcs11Module(), getPassword()).refresh();
    }
}
