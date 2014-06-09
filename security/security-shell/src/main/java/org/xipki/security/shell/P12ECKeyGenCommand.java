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

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.P12KeypairGenerationResult;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p10.P12KeypairGenerator;
import org.xipki.security.p10.P12KeypairGenerator.ECDSAIdentityGenerator;

@Command(scope = "keytool", name = "ec-p12", description="Generate EC keypair in PKCS#12 keystore")
public class P12ECKeyGenCommand extends KeyGenCommand
{
    @Option(name = "-curve",
            description = "EC Curve name, the default is brainpoolP256r1",
            required = false)
    protected String            curveName;

    @Option(name = "-subject",
            required = true, description = "Required. Subject in the self-signed certificate")
    protected String            subject;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#12 file")
    protected String            password;

    @Option(name = "-out",
            required = true, description = "Required. Where to save the key")
    protected String            keyOutFile;

    @Option(name = "-certout",
            required = false, description = "Where to save the self-signed certificate")
    protected String            certOutFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(curveName == null)
        {
            curveName = "brainpoolP256r1";
        }

        char[] pwd = readPasswordIfNotSet(password);
        ECDSAIdentityGenerator gen = new P12KeypairGenerator.ECDSAIdentityGenerator(
                curveName, pwd, subject, getKeyUsage(), getExtendedKeyUsage());

        P12KeypairGenerationResult keyAndCert = gen.generateIdentity();

        File p12File = new File(keyOutFile);
        System.out.println("Saved PKCS#12 keystore in " + p12File.getPath());
        IoCertUtil.save(p12File, keyAndCert.getKeystore());
        if(certOutFile != null)
        {
            File certFile = new File(certOutFile);
            IoCertUtil.save(certFile, keyAndCert.getCertificate().getEncoded());
            System.out.println("Saved self-signed certificate in " + certFile.getPath());
        }

        return null;
    }

}
