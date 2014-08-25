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
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11CryptService;
import org.xipki.security.p11.iaik.IaikP11ModulePool;

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
        char[] pwd = getPassword();

        IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(
                securityFactory.getPkcs11Module());

        IaikExtendedSlot slot = null;
        try
        {
            slot = module.getSlot(new P11SlotIdentifier(slotIndex, null), pwd);
        }catch(SignerException e)
        {
            System.err.println("ERROR:  " + e.getMessage());
            return null;
        }

        char[] keyLabelChars = (keyLabel == null) ?
                null : keyLabel.toCharArray();

        PrivateKey privKey = slot.getPrivateObject(null, null, keyIdentifier.getKeyId(), keyLabelChars);
        if(privKey == null)
        {
            System.err.println("Could not find private key " + keyIdentifier);
            return null;
        }

        Session session = slot.borrowWritableSession();
        try
        {
            try
            {
                session.destroyObject(privKey);
                System.out.println("Deleted private key");
            }catch(TokenException e)
            {
                System.err.println("Could not delete private key");
            }

            PublicKey pubKey = slot.getPublicKeyObject(null, null,
                    privKey.getId().getByteArrayValue(), null);
            if(pubKey != null)
            {
                try
                {
                    session.destroyObject(pubKey);
                    System.out.println("Deleted public key");
                }catch(TokenException e)
                {
                    System.err.println("Could not delete public key");
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
                        System.err.println("Could not delete certificate at index " + i);
                    }
                }
                if(nDeleted > 0)
                {
                    StringBuilder sb = new StringBuilder("Deleted ");
                    sb.append(nDeleted);
                    sb.append(nDeleted == 1 ? " certificate" : " certificates");
                    System.out.println(sb.toString());
                }
            }

            IaikP11CryptService p11CryptService = IaikP11CryptService.getInstance(
                    securityFactory.getPkcs11Module(), pwd);
            p11CryptService.refresh();
        }finally
        {
            slot.returnWritableSession(session);
        }

        return null;
    }
}
