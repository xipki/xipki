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

package org.xipki.security.p11.sun;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

import sun.security.pkcs11.wrapper.PKCS11Exception;

@SuppressWarnings("restriction")
public final class SunP11CryptService implements P11CryptService
{
    private static final Logger LOG = LoggerFactory.getLogger(SunP11CryptService.class);

    private final ConcurrentSkipListSet<SunP11Identity> identities = new ConcurrentSkipListSet<>();

    private String pkcs11Module;
    private char[] password;
    private Set<Integer> includeSlotIndexes;
    private Set<Integer> excludeSlotIndexes;

    private static final Map<String, SunP11CryptService> instances = new HashMap<>();

    public static SunP11CryptService getInstance(String pkcs11Module, char[] password,
            Set<Integer> includeSlotIndexes, Set<Integer> excludeSlotIndexes)
    throws SignerException
    {
        SunNamedCurveExtender.addNamedCurves();

        synchronized (instances)
        {
            SunP11CryptService instance = instances.get(pkcs11Module);
            if(instance == null)
            {
                instance = new SunP11CryptService(pkcs11Module, password, includeSlotIndexes, excludeSlotIndexes);
                instances.put(pkcs11Module, instance);
            }

            return instance;
        }
    }

    private SunP11CryptService(String pkcs11Module, char[] password,
            Set<Integer> includeSlotIndexes, Set<Integer> excludeSlotIndexes)
    throws SignerException
    {
        ParamChecker.assertNotEmpty("pkcs11Module", pkcs11Module);
        this.pkcs11Module = pkcs11Module;

        // Keystore does not allow emptry pin
        this.password = (password == null) ? "dummy".toCharArray() : password;
        this.includeSlotIndexes = includeSlotIndexes == null ?
                null : new HashSet<>(includeSlotIndexes);
        this.excludeSlotIndexes = excludeSlotIndexes == null ?
                null : new HashSet<>(excludeSlotIndexes);

        int idx_sunec = -1;
        int idx_xipki = -1;

        Provider xipkiProv = null;
        Provider[] providers = Security.getProviders();
        int n = providers.length;
        for(int i = 0; i < n; i++)
        {
            String name = providers[i].getName();
            if("SunEC".equals(name))
            {
                idx_sunec = i;
            }
            else if(XiPKISunECProvider.NAME.equals(name))
            {
                xipkiProv = providers[i];
                idx_xipki = i;
            }
        }

        if(idx_sunec != -1)
        {
            if(xipkiProv == null)
            {
                xipkiProv = new XiPKISunECProvider();
                idx_xipki = providers.length;
            }
            else if(idx_sunec < idx_xipki)
            {
                Security.removeProvider(XiPKISunECProvider.NAME);
            }

            if(idx_sunec < idx_xipki)
            {
                Security.insertProviderAt(xipkiProv, idx_sunec+1);
            }

            providers = Security.getProviders();
            n = providers.length;
            for(int i = 0; i < n; i++)
            {
                String name = providers[i].getName();
                LOG.info("provider[" + i + "]: " + name);
            }
        }

        refresh();
    }

    @Override
    public synchronized void refresh()
    throws SignerException
    {
        Set<SunP11Identity> currentIdentifies = new HashSet<>();

        // try to initialize with the slot 0
        Provider p11ProviderOfSlot0 = getPKCS11Provider(pkcs11Module, 0);

        long[] slotList = allSlots(pkcs11Module);

        for(int i = 0; i < slotList.length; i++)
        {
            if(excludeSlotIndexes != null && excludeSlotIndexes.contains(i))
            {
                continue;
            }

            if(includeSlotIndexes != null && includeSlotIndexes.contains(i) == false)
            {
                continue;
            }

            try
            {
                Provider provider;
                if(i == 0)
                {
                    provider = p11ProviderOfSlot0;
                }
                else
                {
                    provider = getPKCS11Provider(pkcs11Module, i);
                }

                PKCS11SlotIdentifier slotId = new PKCS11SlotIdentifier(i, slotList[i]);

                KeyStore keystore = KeyStore.getInstance("PKCS11", provider);

                try
                {
                    keystore.load(null, password);
                } catch (Exception e)
                {
                    throw new SignerException(e);
                }

                Enumeration<String> aliases = keystore.aliases();
                while(aliases.hasMoreElements())
                {
                    String alias = aliases.nextElement();
                    try
                    {
                        if(keystore.isKeyEntry(alias) == false)
                        {
                            continue;
                        }

                        Key key = keystore.getKey(alias, password);
                        if(key instanceof PrivateKey == false)
                        {
                            continue;
                        }

                        SunP11Identity oldIdentity = getIdentity(slotId, new Pkcs11KeyIdentifier(alias));
                        if(oldIdentity != null)
                        {
                            currentIdentifies.add(oldIdentity);
                            continue;
                        }

                        PrivateKey signatureKey = (PrivateKey) key;
                        X509Certificate signatureCert = (X509Certificate) keystore.getCertificate(alias);
                        PublicKey pubKey = signatureCert.getPublicKey();

                        Certificate[] certchain = keystore.getCertificateChain(alias);
                        X509Certificate[] x509Certchain = new X509Certificate[certchain.length];
                        for(int j = 0; j < certchain.length; j++)
                        {
                            x509Certchain[j] = (X509Certificate) certchain[j];
                        }

                        if("EC".equalsIgnoreCase(pubKey.getAlgorithm()))
                        {
                            if(pubKey instanceof ECPublicKey == false)
                            {
                                // reparse the certificate due to bug in bcprov version 1.49
                                signatureCert = IoCertUtil.parseCert(signatureCert.getEncoded());
                                pubKey = signatureCert.getPublicKey();
                            }
                        }

                        SunP11Identity p11Identity = new SunP11Identity(provider, slotId, alias, signatureKey,
                                x509Certchain, pubKey);
                        currentIdentifies.add(p11Identity);
                    }catch(SignerException e)
                    {
                        String msg = "SignerException while constructing SunP11Identity for alias " + alias +
                                " (slot: " + i + ", module: " + pkcs11Module + ")";
                        LOG.warn(msg + ", message: {}", e.getMessage());
                        LOG.debug(msg, e);
                        continue;
                    }
                }
            }catch(Throwable t)
            {
                String msg = "Could not initialize PKCS11 slot " + i + " (module: " + pkcs11Module + ")";
                LOG.warn(msg + ", message: {}", t.getMessage());
                LOG.debug(msg, t);
                continue;
            }
        }

        this.identities.clear();
        this.identities.addAll(currentIdentifies);
        currentIdentifies.clear();
        currentIdentifies = null;

        if(LOG.isInfoEnabled())
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Initialized ").append(this.identities.size()).append(" PKCS#11 Keys:\n");
            for(SunP11Identity identity : this.identities)
            {
                sb.append("\t(slot ").append(identity.getSlotId());
                sb.append(", algo=").append(identity.getPublicKey().getAlgorithm());
                sb.append(", label=").append(identity.getKeyLabel()).append(")\n");
            }

            LOG.info(sb.toString());
        }
    }

    private static Provider getPKCS11Provider(String pkcs11Module, int slotIndex)
    {
        File f = new File(pkcs11Module);

        StringBuilder sb = new StringBuilder();
        sb.append("Slot-").append(slotIndex);
        sb.append("_Lib-").append(f.getName());

        String name = sb.toString();

        Provider p = Security.getProvider("SunPKCS11-" + name);
        if(p != null)
        {
            return p;
        }

        sb = new StringBuilder();
        sb.append("name = ").append(name).append("\n");
        sb.append("slotListIndex = ").append(slotIndex).append("\n");

        sb.append("library = ").append(pkcs11Module).append("\n");

        byte[] pkcs11configBytes = sb.toString().getBytes();

        ByteArrayInputStream configStream = new ByteArrayInputStream(pkcs11configBytes);
        p = new sun.security.pkcs11.SunPKCS11(configStream);
        Security.addProvider(p);

        return p;
    }

    private static long[] allSlots(String pkcs11Module)
    throws SignerException
    {
        String functionList = null;
        sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS pInitArgs = null;
        boolean omitInitialize = true;

        sun.security.pkcs11.wrapper.PKCS11 pkcs11;
        try
        {
            pkcs11 = sun.security.pkcs11.wrapper.PKCS11.getInstance(
                    pkcs11Module, functionList, pInitArgs, omitInitialize);
        } catch (IOException e)
        {
            throw new SignerException("IOException: " + e.getMessage(), e);
        } catch (PKCS11Exception e)
        {
            throw new SignerException("PKCS11Exception: " + e.getMessage(), e);
        }

        long[] slotList;
        try
        {
            slotList = pkcs11.C_GetSlotList(false);
        } catch (PKCS11Exception e)
        {
            throw new SignerException("PKCS11Exception: " + e.getMessage(), e);
        }
        return slotList;
    }

    @Override
    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo, PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        ensureResource();

        SunP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no key with " + keyId);
        }

        return identity.CKM_RSA_PKCS(encodedDigestInfo);
    }

    @Override
    public byte[] CKM_RSA_X509(byte[] hash, PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        ensureResource();

        SunP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no key with " + keyId);
        }

        return identity.CKM_RSA_X_509(hash);
    }

    @Override
    public byte[] CKM_ECDSA(byte[] hash, PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        ensureResource();

        SunP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no key with " + keyId);
        }

        return identity.CKM_ECDSA(hash);
    }

    @Override
    public PublicKey getPublicKey(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        SunP11Identity identity = getIdentity(slotId, keyId);
        return identity == null ? null : identity.getPublicKey();
    }

    @Override
    public X509Certificate getCertificate(PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        SunP11Identity identity = getIdentity(slotId, keyId);
        return identity == null ? null : identity.getCertificate();
    }

    private SunP11Identity getIdentity(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        if(keyId.getKeyLabel() == null)
        {
            throw new SignerException("Only key referencing by key-label is supported");
        }

        for(SunP11Identity identity : identities)
        {
            if(identity.match(slotId, keyId.getKeyLabel()))
            {
                return identity;
            }
        }

        return null;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("SunP11CryptService\n");
        sb.append("\tModule: ").append(pkcs11Module).append("\n");
        return sb.toString();
    }

    @Override
    public X509Certificate[] getCertificates(PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        SunP11Identity identity = getIdentity(slotId, keyId);
        return identity == null ? null : identity.getCertificateChain();
    }

    @Override
    public PKCS11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException
    {
        List<PKCS11SlotIdentifier> slotIds = new LinkedList<>();
        for(SunP11Identity identity : identities)
        {
            PKCS11SlotIdentifier slotId = identity.getSlotId();
            if(slotIds.contains(slotId) == false)
            {
                slotIds.add(slotId);
            }
        }

        return slotIds.toArray(new PKCS11SlotIdentifier[0]);
    }

    @Override
    public String[] getKeyLabels(PKCS11SlotIdentifier slotId)
    throws SignerException
    {
        List<String> keyLabels = new LinkedList<>();
        for(SunP11Identity identity : identities)
        {
            if(slotId.equals(identity.getSlotId()))
            {
                keyLabels.add(identity.getKeyLabel());
            }
        }

        return keyLabels.toArray(new String[0]);
    }

    private synchronized void ensureResource()
    {
    }
}
