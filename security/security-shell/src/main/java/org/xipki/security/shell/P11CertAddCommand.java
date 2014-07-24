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

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11CryptService;
import org.xipki.security.p11.iaik.IaikP11ModulePool;
import org.xipki.security.p11.iaik.IaikP11Util;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "add-cert", description="Add certificate to PKCS#11 device")
public class P11CertAddCommand extends SecurityCommand
{

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer slotIndex;

    @Option(name = "-cert",
            required = true, description = "Required. Certificate file")
    protected String certFile;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#11 device")
    protected String password;

    @Option(name = "-p",
            required = false, description = "Read password from console")
    protected Boolean readFromConsole;

    @Override
    protected Object doExecute()
    throws Exception
    {
        IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(
                securityFactory.getPkcs11Module());

        char[] pwd = readPasswordIfRequired(password, readFromConsole);
        IaikExtendedSlot slot = null;
        try
        {
            slot = module.getSlot(new PKCS11SlotIdentifier(slotIndex, null), pwd);
        }catch(SignerException e)
        {
            System.err.println("ERROR:  " + e.getMessage());
            return null;
        }

        X509Certificate cert = IoCertUtil.parseCert(certFile);

        Session session = slot.borrowWritableSession();
        try
        {
            byte[] encodedCert = cert.getEncoded();

            X509PublicKeyCertificate[] certObjs = slot.getCertificateObjects(cert.getSubjectX500Principal());
            if(certObjs != null)
            {
                for(X509PublicKeyCertificate certObj : certObjs)
                {
                    if(Arrays.equals(encodedCert, certObj.getValue().getByteArrayValue()))
                    {
                        Pkcs11KeyIdentifier p11KeyId = new Pkcs11KeyIdentifier(
                                certObj.getId().getByteArrayValue(),
                                new String(certObj.getLabel().getCharArrayValue()));
                        System.out.println("Given certificate already exists under " + p11KeyId);
                        return null;
                    }
                }
            }

            byte[] keyId = IaikP11Util.generateKeyID(session);
            X509PublicKeyCertificate newCaCertTemp = P11CertUpdateCommand.createPkcs11Template(
                    cert, encodedCert, keyId, null);
            session.createObject(newCaCertTemp);
            Pkcs11KeyIdentifier p11KeyId = new Pkcs11KeyIdentifier(keyId,
                    new String(newCaCertTemp.getLabel().getCharArrayValue()));
            System.out.println("Added certificate under " + p11KeyId);
        }finally
        {
            slot.returnWritableSession(session);
        }

        IaikP11CryptService.getInstance(securityFactory.getPkcs11Module(), pwd, null, null).refresh();
        return null;
    }

}
