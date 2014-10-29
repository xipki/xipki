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
import org.xipki.common.IoCertUtil;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
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
                        P11KeyIdentifier p11KeyId = new P11KeyIdentifier(
                                certObj.getId().getByteArrayValue(),
                                new String(certObj.getLabel().getCharArrayValue()));
                        err("Given certificate already exists under " + p11KeyId);
                        return null;
                    }
                }
            }

            byte[] keyId = IaikP11Util.generateKeyID(session);
            X509PublicKeyCertificate newCaCertTemp = P11CertUpdateCommand.createPkcs11Template(
                    cert, encodedCert, keyId, null);
            session.createObject(newCaCertTemp);
            P11KeyIdentifier p11KeyId = new P11KeyIdentifier(keyId,
                    new String(newCaCertTemp.getLabel().getCharArrayValue()));
            out("Added certificate under " + p11KeyId);
        }finally
        {
            slot.returnWritableSession(session);
        }

        securityFactory.getP11CryptService(moduleName).refresh();
        return null;
    }

}
