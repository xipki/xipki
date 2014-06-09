/*
 * Copyright (c) 2014 xipki.org
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

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11CryptService;
import org.xipki.security.p11.iaik.IaikP11ModulePool;

@Command(scope = "keytool", name = "add-cert", description="Add certificate to PKCS#11 device")
public class P11CertAddCommand extends SecurityCommand
{

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer           slotIndex;

    @Option(name = "-cert",
            required = true, description = "Required. Certificate file")
    protected String            certFile;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#11 device")
    protected String            password;
    
    @Option(name = "-p",
            required = false, description = "Read password from console")
    protected Boolean            readFromConsole;
    
    @Override
    protected Object doExecute()
    throws Exception
    {
        IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(
                securityFactory.getPkcs11Module());

        char[] pwd = readPasswordIfNotSet(password, readFromConsole);
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

            boolean alreadyExists = false;
            X509PublicKeyCertificate[] certObjs = slot.getCertificateObjects(cert.getSubjectX500Principal());
            if(certObjs != null)
            {
                for(X509PublicKeyCertificate certObj : certObjs)
                {
                    if(Arrays.equals(encodedCert, certObj.getValue().getByteArrayValue()))
                    {
                        alreadyExists = true;
                        break;
                    }
                }
            }

            if(alreadyExists == false)
            {
                X509PublicKeyCertificate newCaCertTemp = P11CertUpdateCommand.createPkcs11Template(
                		cert, encodedCert, null, null);
                session.createObject(newCaCertTemp);
            }
        }finally
        {
            slot.returnWritableSession(session);
        }

        IaikP11CryptService.getInstance(securityFactory.getPkcs11Module(), pwd, null, null).refresh();
        System.out.println("Updated certificate");
        return null;
    }

}
