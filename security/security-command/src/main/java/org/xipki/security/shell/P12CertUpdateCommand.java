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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.xipki.security.NopPasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "keytool", name = "update-cert-p12", description="Update certificate in PKCS#12 keystore")
public class P12CertUpdateCommand extends OsgiCommandSupport
{
    @Option(name = "-p12",
            required = true, description = "Required. PKCS#12 keystore file")
    protected String            p12File;

    @Option(name = "-pwd", aliases = { "--password" },
            required = true, description = "Required. Password of the PKCS#12 file")
    protected String            password;

    @Option(name = "-cert",
            required = true, description = "Required. Certificate file")
    protected String            certFile;

    private SecurityFactory securityFactory;

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

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

        X509Certificate newCert = IoCertUtil.parseCert(certFile);

        assertMatch(newCert);

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

        Key key = ks.getKey(keyname, pwd);
        Certificate[] chain = new Certificate[]{newCert};
        ks.setKeyEntry(keyname, key, pwd, chain);

        FileOutputStream fOut = null;
        try
        {
            fOut = new FileOutputStream(p12File);
            ks.store(fOut, pwd);
            System.out.println("Updated certificate");
            return null;
        }finally
        {
            if(fOut != null)
            {
                fOut.close();
            }
        }
    }

    private void assertMatch(X509Certificate cert) throws SignerException, PasswordResolverException
    {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("keystore", "file:" + p12File);
        if(password != null)
        {
            pairs.putUtf8Pair("password", new String(password));
        }

        PublicKey pubKey = cert.getPublicKey();
        if(pubKey instanceof RSAPublicKey)
        {
            pairs.putUtf8Pair("algo", "SHA1withRSA");
        }
        else if(pubKey instanceof ECPublicKey)
        {
            pairs.putUtf8Pair("algo", "SHA1withECDSA");
        }
        else
        {
            throw new SignerException("Unknown key type: " + pubKey.getClass().getName());
        }

        securityFactory.createSigner("PKCS12", pairs.getEncoded(), cert, NopPasswordResolver.INSTANCE);
    }

}
