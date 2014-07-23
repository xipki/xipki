/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.PBEPasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "pbe-dec", description="Decrypt password with master password")
public class PBEDecryptCommand extends SecurityCommand
{
    @Option(name = "-pwd", aliases = { "--password" },
            required = true, description = "Required. Encrypted password, starts with PBE:")
    protected String            passwordHint;

    @Override
    protected Object doExecute()
    throws Exception
    {
        char[] masterPassword = readPassword("Please enter the master password");
        if(passwordHint.startsWith("PBE:") == false)
        {
            System.err.println("encrypted password '" + passwordHint + "' does not start with PBE:");
            return null;
        }

        try
        {
            char[] password = PBEPasswordResolver.resolvePassword(masterPassword, passwordHint);
            System.out.println("The decrypted password is: '" + new String(password) + "'");
        }catch(Exception e)
        {
            System.err.println(e.getMessage());
        }
        return null;
    }

}
