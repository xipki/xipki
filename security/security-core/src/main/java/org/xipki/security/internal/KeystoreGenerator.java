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

package org.xipki.security.internal;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.security.common.IoCertUtil;

public class KeystoreGenerator
{
    final static String baseDir = "/home/lliao/xipki/output2/";
    public static void main(String[] args)
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());
            generateKeystores("1234".toCharArray());
        } catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    private static void generateKeystores(char[] password)
    throws Exception
    {
        X509Certificate rca1Cert = IoCertUtil.parseCert(baseDir + "RCA1.der");

        X509Certificate localhostCert = IoCertUtil.parseCert(baseDir + "TLS-localhost.der");
        PrivateKey localhostKey  = extractPrivateKey(baseDir + "TLS-localhost.p12", password);

        // Keystore tls-server-keystore.jks
        Set<String> aliases = new HashSet<String>();
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, password);
        ks.setKeyEntry(getAlias(localhostCert, aliases), localhostKey, password,
                new X509Certificate[]{localhostCert, rca1Cert});
        FileOutputStream out = new FileOutputStream(baseDir + "tls-server-keystore.jks");
        ks.store(out, password);
        out.close();

        // Keystore tls-truststore.jks
        aliases.clear();
        ks = KeyStore.getInstance("JKS");
        ks.load(null, password);
        ks.setCertificateEntry(getAlias(rca1Cert, aliases), rca1Cert);
        out = new FileOutputStream(baseDir + "tls-truststore.jks");
        ks.store(out, password);
        out.close();

        X509Certificate client1Cert = IoCertUtil.parseCert(baseDir + "TLS-client1.der");
        PrivateKey client1Key  = extractPrivateKey(baseDir + "TLS-client1.p12", password);
        // Keystore tls-p11server-truststore.jks
        aliases.clear();
        ks = KeyStore.getInstance("JKS");
        ks.load(null, password);
        ks.setCertificateEntry(getAlias(rca1Cert, aliases), client1Cert);
        out = new FileOutputStream(baseDir + "tls-p11server-truststore.jks");
        ks.store(out, password);
        out.close();

        // Keystore tls-client-keystore.jks
        aliases.clear();
        ks = KeyStore.getInstance("JKS");
        ks.load(null, password);
        ks.setKeyEntry(getAlias(client1Cert, aliases), client1Key, password,
                new X509Certificate[]{client1Cert});
        out = new FileOutputStream(baseDir + "tls-p11client-keystore.jks");
        ks.store(out, password);
        out.close();
    }

    private static PrivateKey extractPrivateKey(String filename, char[] password)
    throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(filename), password);
        Enumeration<String> aliases = ks.aliases();
        String alias = null;
        while(aliases.hasMoreElements())
        {
            String t = aliases.nextElement();
            if(ks.isKeyEntry(t))
            {
                alias = t;
                break;
            }
        }

        return (PrivateKey) ks.getKey(alias, password);
    }

    private static String getAlias(X509Certificate cert, Set<String> existingAliases)
    throws Exception
    {
        String cn = getCommonName(cert);

        String alias = cn;

        int i = 1;
        while(existingAliases.contains(alias))
        {
            alias = cn + "-" + (i++);
        }
        existingAliases.add(alias);
        return alias;
    }

    private static String getCommonName(X509Certificate cert)
    throws Exception
    {
        X500Name name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        ASN1Encodable cnValue = name.getRDNs(new ASN1ObjectIdentifier("2.5.4.3"))[0].getFirst().getValue();
        return IETFUtils.valueToString(cnValue);
    }
}
