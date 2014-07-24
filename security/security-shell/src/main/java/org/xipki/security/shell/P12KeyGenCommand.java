/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.File;
import java.io.IOException;

import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.P12KeypairGenerationResult;

/**
 * @author Lijun Liao
 */

public abstract class P12KeyGenCommand extends KeyGenCommand
{

    @Option(name = "-subject",
            required = true, description = "Required. Subject in the self-signed certificate")
    protected String            subject;

    @Option(name = "-out",
            required = true, description = "Required. Where to save the key")
    protected String            keyOutFile;

    @Option(name = "-certout",
            required = false, description = "Where to save the self-signed certificate")
    protected String            certOutFile;

    protected void saveKeyAndCert(P12KeypairGenerationResult keyAndCert)
    throws IOException
    {
        File p12File = new File(keyOutFile);
        System.out.println("Saved PKCS#12 keystore in " + p12File.getPath());
        saveVerbose("Saved PKCS#12 keystore to file", p12File, keyAndCert.getKeystore());
        if(certOutFile != null)
        {
            File certFile = new File(certOutFile);
            saveVerbose("Saved self-signed certificate to file", certFile,
                    keyAndCert.getCertificate().getEncoded());
        }
    }

    protected char[] getPassword()
    {
        char[] pwdInChar = readPasswordIfNotSet(password);
        if(pwdInChar != null)
        {
            password = new String(pwdInChar);
        }
        return pwdInChar;
    }

}
