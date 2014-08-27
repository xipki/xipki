/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.OBFPasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "deobfuscate", description="Deobfuscate password")
public class DeobfuscateCommand extends SecurityCommand
{
    @Option(name = "-pwd", aliases = { "--password" },
            required = true, description = "Required. Obfuscated password, starts with OBF:")
    protected String passwordHint;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(passwordHint.startsWith("OBF:") == false)
        {
            err("encrypted password '" + passwordHint + "' does not start with OBF:");
            return null;
        }

        try
        {
            String password = OBFPasswordResolver.deobfuscate(passwordHint);
            out("The deobfuscated password is: '" + new String(password) + "'");
        }catch(Exception e)
        {
            err(e.getMessage());
        }
        return null;
    }

}
