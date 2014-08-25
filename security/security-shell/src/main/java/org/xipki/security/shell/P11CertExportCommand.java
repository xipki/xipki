/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import java.io.File;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11ModulePool;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "export-cert", description="Export certificate from PKCS#11 device")
public class P11CertExportCommand extends P11SecurityCommand
{

    @Option(name = "-out",
            required = true, description = "Required. Where to save the certificate")
    protected String outFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(
                securityFactory.getPkcs11Module());

        P11KeyIdentifier keyIdentifier = getKeyIdentifier();
        char[] pwd = getPassword();

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

        X509PublicKeyCertificate cert = slot.getCertificateObject(privKey.getId().getByteArrayValue(), null);
        if(cert == null)
        {
            System.err.println("Could not find certificate " + keyIdentifier);
            return null;
        }

        saveVerbose("Saved certificate to file", new File(outFile), cert.getValue().getByteArrayValue());
        return null;
    }

}
