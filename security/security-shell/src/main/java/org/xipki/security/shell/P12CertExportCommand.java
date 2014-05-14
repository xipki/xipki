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

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "keytool", name = "export-cert-p12", description="Export certificate from PKCS#12 keystore")
public class P12CertExportCommand extends SecurityCommand
{
    @Option(name = "-p12",
            required = true, description = "Required. PKCS#12 keystore file")
    protected String            p12File;

    @Option(name = "-pwd", aliases = { "--password" },
            required = true, description = "Required. Password of the PKCS#12 file")
    protected String            password;

    @Option(name = "-out",
            required = true, description = "Required. Where to save the certificate")
    protected String            outFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        KeyStore ks;

        char[] pwd = password.toCharArray();

        FileInputStream fIn = null;
        try
        {
            fIn = new FileInputStream(p12File);
            ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(fIn, pwd);
        }finally
        {
            if(fIn != null)
            {
                fIn.close();
            }
        }

        String keyname = null;
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements())
        {
            String alias = aliases.nextElement();
            if(ks.isKeyEntry(alias))
            {
                keyname = alias;
                break;
            }
        }

        if(keyname == null)
        {
            throw new SignerException("Could not find private key");
        }

        X509Certificate cert = (X509Certificate) ks.getCertificate(keyname);
        IoCertUtil.save(new File(outFile), cert.getEncoded());
        System.out.println("Saved certificate in " + outFile);

        return null;
    }

}
