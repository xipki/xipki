/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "rm-cert", description="Remove certificate from PKCS#11 device")
public class P11CertDeleteCommand extends SecurityCommand
{
    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer slotIndex;

    @Option(name = "-key-id",
            required = true, description = "Required. Id of the certificate in the PKCS#11 device")
    protected String keyId;

    @Option(name = "-module",
            required = false, description = "Name of the PKCS#11 module.")
    protected String moduleName = SecurityFactory.DEFAULT_P11MODULE_NAME;

    @Override
    protected Object doExecute()
    throws Exception
    {
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

        X509PublicKeyCertificate[] existingCerts = slot.getCertificateObjects(
                Hex.decode(keyId), null);

        if(existingCerts == null || existingCerts.length == 0)
        {
            err("Could not find certificates with id " + keyId);
            return null;
        }

        Session session = slot.borrowWritableSession();
        try
        {
            for(X509PublicKeyCertificate cert : existingCerts)
            {
                session.destroyObject(cert);
            }
        }finally
        {
            slot.returnWritableSession(session);
        }

        securityFactory.getP11CryptService(moduleName).refresh();
        int n = existingCerts.length;
        out("Deleted " + n + " certificate" + (n > 1 ? "s" : ""));
        return null;
    }

}
