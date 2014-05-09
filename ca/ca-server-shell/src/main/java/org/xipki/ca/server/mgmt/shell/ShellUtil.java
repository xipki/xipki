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

package org.xipki.ca.server.mgmt.shell;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;

class ShellUtil
{
    static String replaceFileInSignerConf(String keystoreType, String signerConf,
            PasswordResolver passwordResolver)
    throws Exception
    {
        if(signerConf.contains("file:") == false)
        {
            return signerConf;
        }

        CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(signerConf);
        String keystoreConf = utf8Pairs.getValue("keystore");
        if(keystoreConf.startsWith("file:") == false)
        {
            return signerConf;
        }

        String keystoreFile = keystoreConf.substring("file:".length());
        String passwordHint = utf8Pairs.getValue("password");
        String keyLabel     = utf8Pairs.getValue("key-label");

        byte[] minimalKeystoreBytes = extractMinimalKeyStore(keystoreType, keystoreFile, keyLabel,
                passwordResolver.resolvePassword(passwordHint));
        utf8Pairs.putUtf8Pair("keystore", "base64:" + Base64.toBase64String(minimalKeystoreBytes));
        return utf8Pairs.getEncoded();
    }

    private static byte[] extractMinimalKeyStore(String keystoreType, String keystoreFile,
            String keyname, char[] password)
    throws Exception
    {
        KeyStore ks;
        if("JKS".equalsIgnoreCase(keystoreType))
        {
            ks = KeyStore.getInstance(keystoreType);
        }
        else
        {
             ks = KeyStore.getInstance(keystoreType, "BC");
        }
        ks.load(new FileInputStream(keystoreFile), password);

        if(keyname == null)
        {
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
        }
        else
        {
            if(ks.isKeyEntry(keyname) == false)
            {
                throw new KeyStoreException("unknown key named " + keyname);
            }
        }

        Certificate[] certs = ks.getCertificateChain(keyname);
        if(certs == null || certs.length == 1)
        {
            return IoCertUtil.read(keystoreFile);
        }

        PrivateKey key = (PrivateKey) ks.getKey(keyname, password);

        KeyStore ks2;
        if("JKS".equalsIgnoreCase(keystoreType))
        {
            ks2 = KeyStore.getInstance(keystoreType);
        }
        else
        {
             ks2 = KeyStore.getInstance(keystoreType, "BC");
        }
        ks2.load(null, password);
        ks.setKeyEntry(keyname, key, password, new Certificate[]{certs[0]});
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ks.store(bout, password);
        byte[] bytes = bout.toByteArray();
        bout.close();
        return bytes;
    }

}
