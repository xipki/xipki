/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.FileInputStream;
import java.security.KeyStore;

import org.apache.felix.gogo.commands.Option;

/**
 * @author Lijun Liao
 */

public abstract class P12SecurityCommand extends SecurityCommand
{
    @Option(name = "-p12",
            required = true, description = "Required. PKCS#12 keystore file")
    protected String p12File;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#12 file")
    protected String password;

    protected char[] getPassword()
    {
        char[] pwdInChar = readPasswordIfNotSet(password);
        if(pwdInChar != null)
        {
            password = new String(pwdInChar);
        }
        return pwdInChar;
    }

    protected KeyStore getKeyStore()
    throws Exception
    {
        KeyStore ks;

        FileInputStream fIn = null;
        try
        {
            fIn = new FileInputStream(expandFilepath(p12File));
            ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(fIn, getPassword());
        }finally
        {
            if(fIn != null)
            {
                fIn.close();
            }
        }

        return ks;
    }
}
