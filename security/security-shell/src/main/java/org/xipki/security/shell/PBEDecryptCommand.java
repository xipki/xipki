/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
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
