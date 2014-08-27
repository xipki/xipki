/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import org.apache.felix.gogo.commands.Command;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "delete-key", description="Generate EC keypair in PKCS#11 device")
public class P11KeyDeleteCommand extends P11SecurityCommand
{
    @Override
    protected Object doExecute()
    throws Exception
    {
        P11KeyIdentifier keyIdentifier = getKeyIdentifier();
        IaikExtendedModule module = getModule(moduleName);

        IaikExtendedSlot slot = null;
        try
        {
            slot = module.getSlot(new P11SlotIdentifier(slotIndex, null));
        }catch(SignerException e)
        {
            err("ERROR:  " + e.getMessage());
            return null;
        }

        char[] keyLabelChars = (keyLabel == null) ?
                null : keyLabel.toCharArray();

        PrivateKey privKey = slot.getPrivateObject(null, null, keyIdentifier.getKeyId(), keyLabelChars);
        if(privKey == null)
        {
            err("Could not find private key " + keyIdentifier);
            return null;
        }

        Session session = slot.borrowWritableSession();
        try
        {
            try
            {
                session.destroyObject(privKey);
                out("Deleted private key");
            }catch(TokenException e)
            {
                err("Could not delete private key");
            }

            PublicKey pubKey = slot.getPublicKeyObject(null, null,
                    privKey.getId().getByteArrayValue(), null);
            if(pubKey != null)
            {
                try
                {
                    session.destroyObject(pubKey);
                    out("Deleted public key");
                }catch(TokenException e)
                {
                    err("Could not delete public key");
                }
            }

            X509PublicKeyCertificate[] certs = slot.getCertificateObjects(privKey.getId().getByteArrayValue(), null);
            if(certs != null && certs.length > 0)
            {
                int nDeleted = 0;
                for(int i = 0; i < certs.length; i++)
                {
                    try
                    {
                        session.destroyObject(certs[i]);
                        nDeleted++;
                    }catch(TokenException e)
                    {
                        err("Could not delete certificate at index " + i);
                    }
                }
                if(nDeleted > 0)
                {
                    StringBuilder sb = new StringBuilder("Deleted ");
                    sb.append(nDeleted);
                    sb.append(nDeleted == 1 ? " certificate" : " certificates");
                    out(sb.toString());
                }
            }

            securityFactory.getP11CryptService(moduleName).refresh();
        }finally
        {
            slot.returnWritableSession(session);
        }

        return null;
    }
}
