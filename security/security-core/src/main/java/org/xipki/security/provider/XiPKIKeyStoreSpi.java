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

package org.xipki.security.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.P11CryptServiceFactory;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;

public class XiPKIKeyStoreSpi extends KeyStoreSpi
{
    private static String defaultPkcs11Module;
    private static String defaultPkcs11Provider;

    private Date creationDate;

    private static class MyEnumeration<E> implements Enumeration<E>
    {
        private Iterator<E> iter;

        public MyEnumeration(Iterator<E> iter)
        {
            this.iter = iter;
        }

        @Override
        public boolean hasMoreElements()
        {
            return iter.hasNext();
        }

        @Override
        public E nextElement()
        {
            return iter.next();
        }
    }

    private static class KeyCertEntry
    {
        private PrivateKey key;
        private Certificate[] chain;

        public KeyCertEntry(PrivateKey key, Certificate[] chain)
        {
            if(chain == null)
            {
                throw new IllegalArgumentException("chain is null");
            }
            if(chain.length < 1)
            {
                throw new IllegalArgumentException("chain does not contain any certificate");
            }
            this.key = key;
            this.chain = chain;
        }

        PrivateKey getKey()
        {
            return key;
        }

        Certificate[] getCertificateChain()
        {
            return Arrays.copyOf(chain, chain.length);
        }

        Certificate getCertificate()
        {
            return chain[0];
        }
    }

    private Map<String, KeyCertEntry> keyCerts = new HashMap<String, KeyCertEntry>();

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException
    {
        this.creationDate = new Date();

        String pkcs11Provider = defaultPkcs11Provider;
        String pkcs11Module = defaultPkcs11Module;

        if(stream != null)
        {
            Properties props = new Properties();
            props.load(stream);

            String s = props.getProperty("pkcs11.provider");
            if(s != null)
            {
                pkcs11Provider = s;
            }

            s = props.getProperty("pkcs11.module");
            if(s != null)
            {
                pkcs11Module = s;
            }
        }

        if(pkcs11Provider == null)
        {
            throw new IllegalArgumentException("pkcs11.provider is not defined");
        }

        if(pkcs11Module == null)
        {
            throw new IllegalArgumentException("pkcs11.module is not defined");
        }

        Object p11Provider;
        try
        {
            Class<?> clazz = Class.forName(pkcs11Provider);
            p11Provider = clazz.newInstance();
        }catch(Exception e)
        {
            throw new IllegalArgumentException(e.getMessage(), e);
        }

        if(p11Provider instanceof P11CryptServiceFactory == false)
        {
            throw new IllegalArgumentException(pkcs11Provider + " does not implement " +
                    P11CryptServiceFactory.class.getName());
        }

        try
        {
            P11CryptService p11Servcie = ((P11CryptServiceFactory) p11Provider).createP11CryptService(pkcs11Module, password);
            PKCS11SlotIdentifier[] slotIds = p11Servcie.getSlotIdentifiers();

            Map<PKCS11SlotIdentifier, String[]> keyLabelsMap = new HashMap<PKCS11SlotIdentifier, String[]>();

            Set<String> allKeyLabels = new HashSet<String>();
            Set<String> duplicatedKeyLabels = new HashSet<String>();

            for(PKCS11SlotIdentifier slotId: slotIds)
            {
                String[] keyLabels = p11Servcie.getKeyLabels(slotId);
                for(String keyLabel : keyLabels)
                {
                    if(allKeyLabels.contains(keyLabel))
                    {
                        duplicatedKeyLabels.add(keyLabel);
                    }
                    allKeyLabels.add(keyLabel);
                }

                keyLabelsMap.put(slotId, keyLabels);
            }

            for(PKCS11SlotIdentifier slotId: slotIds)
            {
                String[] keyLabels = keyLabelsMap.get(slotId);
                for(String keyLabel : keyLabels)
                {
                    String alias = keyLabel;
                    if(duplicatedKeyLabels.contains(keyLabel))
                    {
                        alias += "-slot" + slotId.getSlotIndex();
                    }

                    Pkcs11KeyIdentifier keyId = new Pkcs11KeyIdentifier(keyLabel);
                    P11PrivateKey key = new P11PrivateKey(p11Servcie, slotId, keyId);
                    X509Certificate[] chain = p11Servcie.getCertificates(slotId, keyId);

                    KeyCertEntry keyCertEntry = new KeyCertEntry(key, chain);
                    keyCerts.put(alias, keyCertEntry);
                }
            }

        } catch (SignerException e)
        {
            throw new IllegalArgumentException("SignerException: " + e.getMessage(), e);
        } catch (InvalidKeyException e)
        {
            throw new IllegalArgumentException("InvalidKeyException: " + e.getMessage(), e);
        }
    }

    @Override
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException
    {
    }

    @Override
    public Key engineGetKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        if(keyCerts.containsKey(alias) == false)
        {
            return null;
        }

        return keyCerts.get(alias).getKey();
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias)
    {
        if(keyCerts.containsKey(alias) == false)
        {
            return null;
        }

        return keyCerts.get(alias).getCertificateChain();
    }

    @Override
    public Certificate engineGetCertificate(String alias)
    {
        if(keyCerts.containsKey(alias) == false)
        {
            return null;
        }

        return keyCerts.get(alias).getCertificate();
    }

    @Override
    public Date engineGetCreationDate(String alias)
    {
        if(keyCerts.containsKey(alias) == false)
        {
            return null;
        }
        return creationDate;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password,
            Certificate[] chain) throws KeyStoreException
    {
        throw new KeyStoreException("Keystore is read only");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
            throws KeyStoreException
    {
        throw new KeyStoreException("Keystore is read only");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert)
            throws KeyStoreException
    {
        throw new KeyStoreException("Keystore is read only");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException
    {
        throw new KeyStoreException("Keystore is read only");
    }

    @Override
    public Enumeration<String> engineAliases()
    {
        return new MyEnumeration<String>(keyCerts.keySet().iterator());
    }

    @Override
    public boolean engineContainsAlias(String alias)
    {
        return keyCerts.containsKey(alias);
    }

    @Override
    public int engineSize()
    {
        return keyCerts.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias)
    {
        if(keyCerts.containsKey(alias) == false)
        {
            return false;
        }

        return keyCerts.get(alias).key != null;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias)
    {
        if(keyCerts.containsKey(alias) == false)
        {
            return false;
        }

        return keyCerts.get(alias).key == null;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert)
    {
        for(String alias : keyCerts.keySet())
        {
            if(keyCerts.get(alias).getCertificate().equals(cert))
            {
                return alias;
            }
        }

        return null;
    }

    public static void setDefaultPkcs11Module(String pkcs11Module)
    {
        defaultPkcs11Module = pkcs11Module;
    }

    public static void setDefaultPkcs11Provider(String pkcs11Provider)
    {
        defaultPkcs11Provider = pkcs11Provider;
    }
}
