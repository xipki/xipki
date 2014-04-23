/*
 * Copyright 2014 xipki.org
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

import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import java.io.File;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11ModulePool;

@Command(scope = "keytool", name = "export-cert", description="Export certificate from PKCS#11 device")
public class P11CertExportCommand extends OsgiCommandSupport
{

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer           slotIndex;

    @Option(name = "-key-id",
            required = false, description = "Id of the private key in the PKCS#11 token. Either keyId or keyLabel must be specified")
    protected String            keyId;

    @Option(name = "-key-label",
            required = false, description = "Label of the private key in the PKCS#11 token. Either keyId or keyLabel must be specified")
    protected String            keyLabel;

    @Option(name = "-out",
            required = true, description = "Required. Where to save the certificate")
    protected String            outFile;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#11 device")
    protected char[]            password;

    private SecurityFactory securityFactory;

    public SecurityFactory getSecurityFactory()
    {
        return securityFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    @Override
    protected Object doExecute()
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

        IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(
                securityFactory.getPkcs11Module());

        IaikExtendedSlot slot = null;
        try
        {
            slot = module.getSlot(new PKCS11SlotIdentifier(slotIndex, null), password);
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

        IoCertUtil.save(new File(outFile), cert.getValue().getByteArrayValue());
        System.out.println("Saved certificate in " + outFile);
        return null;
    }

}
