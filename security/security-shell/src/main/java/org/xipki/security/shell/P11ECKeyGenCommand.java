/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.File;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.api.P11KeypairGenerationResult;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.p11.iaik.IaikP11CryptService;
import org.xipki.security.p11.iaik.P11KeypairGenerator;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "ec", description="Generate EC keypair in PKCS#11 device")
public class P11ECKeyGenCommand extends KeyGenCommand
{
    @Option(name = "-curve",
            description = "EC Curve name, the default is brainpoolP256r1",
            required = false)
    protected String            curveName;

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer           slotIndex;

    @Option(name = "-key-label",
            required = true, description = "Required. Label of the PKCS#11 objects")
    protected String            label;

    @Option(name = "-subject",
            required = false, description = "Subject in the self-signed certificate")
    protected String            subject;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#11 token")
    protected String            password;

    @Option(name = "-certout",
            required = false, description = "Where to save the self-signed certificate")
    protected String            outputFilename;

    @Option(name = "-p",
            required = false, description = "Read password from console")
    protected Boolean            readFromConsole;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(curveName == null)
        {
            curveName = "brainpoolP256r1";
        }

        if(subject == null || subject.isEmpty())
        {
            subject = "CN=" + label;
        }

        char[] pwd = readPasswordIfRequired(password, readFromConsole);

        P11KeypairGenerator gen = new P11KeypairGenerator();
        P11KeypairGenerationResult keyAndCert = gen.generateECDSAKeypairAndCert(
                securityFactory.getPkcs11Module(), new PKCS11SlotIdentifier(slotIndex, null), pwd,
                curveName, label, subject,
                getKeyUsage(), getExtendedKeyUsage());

        System.out.println("key id: " + Hex.toHexString(keyAndCert.getId()));
        System.out.println("key label: " + keyAndCert.getLabel());
        if(outputFilename != null)
        {
            File certFile = new File(outputFilename);
            saveVerbose("Saved self-signed certificate to file", certFile, keyAndCert.getCertificate().getEncoded());
        }

        IaikP11CryptService.getInstance(securityFactory.getPkcs11Module(), pwd).refresh();

        return null;
    }

}
