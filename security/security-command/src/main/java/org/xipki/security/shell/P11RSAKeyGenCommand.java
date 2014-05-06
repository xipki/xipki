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
import java.math.BigInteger;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.api.P11KeypairGenerationResult;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p11.iaik.IaikP11CryptService;
import org.xipki.security.p11.iaik.P11KeypairGenerator;

@Command(scope = "keytool", name = "rsa", description="Generate RSA keypair via PKCS#11")
public class P11RSAKeyGenCommand extends KeyGenCommand
{
    @Option(name = "-keysize",
            description = "Keysize in bit, the default is 2048",
            required = false)
    protected Integer            keysize;

    @Option(name = "-e",
            description = "public exponent, the default is 65537",
            required = false)
    protected String            publicExponent;

    @Option(name = "-slot",
            required = true, description = "Required. Slot index")
    protected Integer           slotIndex;

    @Option(name = "-key-label",
            required = true, description = "Required. Label of the PKCS#11 objects")
    protected String            label;

    @Option(name = "-pwd", aliases = { "--password" },
            required = false, description = "Password of the PKCS#11 token")
    protected String            password;

    @Option(name = "-out",
            required = false, description = "Output file name of certificate")
    protected String            outputFilename;

    @Option(name = "-cert-type",
    		required = false, description = "Certificate type of the self signed certificate."
    				+ " Currently only TLS, TLS-C or TLS-S are supported")
    protected String            certType;

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
        if(keysize == null)
        {
            keysize = 2048;
        }
        else if(keysize % 1024 != 0)
        {
            System.err.println("Keysize is not multiple of 1024: " + keysize);
            return null;
        }

        BigInteger _publicExponent;
        if(publicExponent == null)
        {
            _publicExponent = BigInteger.valueOf(65537);
        }
        else
        {
            _publicExponent = new BigInteger(publicExponent);
        }

        if(password == null)
        {
            password = "dummy";
        }
        char[] pwd = password.toCharArray();

        P11KeypairGenerator gen = new P11KeypairGenerator();
        PKCS11SlotIdentifier slotId = new PKCS11SlotIdentifier(slotIndex, null);

        P11KeypairGenerationResult keyAndCert = gen.generateRSAKeypairAndCert(
                securityFactory.getPkcs11Module(), slotId, pwd,
                keysize, _publicExponent,
                label, "CN=" + label,
                getKeyUsage(),
                getExtendedKeyUsage());

        System.out.println("key id: " + Hex.toHexString(keyAndCert.getId()));
        System.out.println("key label: " + keyAndCert.getLabel());
        if(outputFilename != null)
        {
               File certFile = new File(outputFilename);
               IoCertUtil.save(certFile, keyAndCert.getCertificate().getEncoded());
               System.out.println("Saved self-signed certificate in " + certFile.getPath());
        }

        IaikP11CryptService.getInstance(securityFactory.getPkcs11Module(), pwd).refresh();

        return null;
    }

	@Override
	protected String getCertType() {
		return certType;
	}

}
