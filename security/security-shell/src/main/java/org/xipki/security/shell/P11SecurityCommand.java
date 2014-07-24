/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.api.Pkcs11KeyIdentifier;

/**
 * @author Lijun Liao
 */

public abstract class P11SecurityCommand extends SecurityCommand
{
    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer           slotIndex;

    @Option(name = "-key-id",
            required = false, description = "Id of the private key in the PKCS#11 device.\n"
                    + "Either keyId or keyLabel must be specified")
    protected String            keyId;

    @Option(name = "-key-label",
            required = false, description = "Label of the private key in the PKCS#11 device.\n"
                    + "Either keyId or keyLabel must be specified")
    protected String            keyLabel;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#11 device")
    protected String            password;

    @Option(name = "-p",
            required = false, description = "Read password from console")
    protected Boolean            readFromConsole;

    protected char[] getPassword()
    {
        char[] pwdInChar = readPasswordIfRequired(password, readFromConsole);
        if(pwdInChar != null)
        {
            password = new String(pwdInChar);
        }
        return pwdInChar;
    }

    protected Pkcs11KeyIdentifier getKeyIdentifier()
    throws Exception
    {
        Pkcs11KeyIdentifier keyIdentifier;
        if(keyId != null && keyLabel == null)
        {
            keyIdentifier = new Pkcs11KeyIdentifier(Hex.decode(keyId));
        }
        else if(keyId == null && keyLabel != null)
        {
            keyIdentifier = new Pkcs11KeyIdentifier(keyLabel);
        }
        else
        {
            throw new Exception("Exactly one of keyId or keyLabel should be specified");
        }
        return keyIdentifier;
    }

}
