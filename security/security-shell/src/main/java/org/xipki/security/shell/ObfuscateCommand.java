/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import org.apache.felix.gogo.commands.Command;
import org.xipki.security.OBFPasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "obfuscate", description="Obfuscate password")
public class ObfuscateCommand extends SecurityCommand
{
    @Override
    protected Object doExecute()
    throws Exception
    {
        char[] password = readPassword("Please enter the password");

        String passwordHint = OBFPasswordResolver.obfuscate(new String(password));
        out("The obfuscated password is: '" + passwordHint + "'");
        return null;
    }

}
