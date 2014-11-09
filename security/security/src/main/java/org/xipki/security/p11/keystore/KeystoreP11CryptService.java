/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.security.p11.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.IoCertUtil;
import org.xipki.common.LogUtil;
import org.xipki.common.ParamChecker;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class KeystoreP11CryptService implements P11CryptService
{
    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11CryptService.class);

    private final P11ModuleConf moduleConf;

    private static final Map<String, KeystoreP11CryptService> instances = new HashMap<>();

    public static KeystoreP11CryptService getInstance(P11ModuleConf moduleConf)
    throws SignerException
    {
        synchronized (instances)
        {
            final String name = moduleConf.getName();
            KeystoreP11CryptService instance = instances.get(name);
            if(instance == null)
            {
                instance = new KeystoreP11CryptService(moduleConf);
                instances.put(name, instance);
            }

            return instance;
        }
    }

    public KeystoreP11CryptService(P11ModuleConf moduleConf)
    throws SignerException
    {
        ParamChecker.assertNotNull("moduleConf", moduleConf);
        this.moduleConf = moduleConf;
        refresh();
    }

    private final ConcurrentSkipListSet<KeystoreP11Identity> identities = new ConcurrentSkipListSet<>();

    @Override
    public synchronized void refresh()
    throws SignerException
    {
        final String nativeLib = moduleConf.getNativeLibrary();

        Set<KeystoreP11Identity> currentIdentifies = new HashSet<>();

        Map<Integer, Long> slotIndexIdMap = new HashMap<>();
        File baseDir = new File(IoCertUtil.expandFilepath(nativeLib));
        File[] children = baseDir.listFiles();
        for(File child : children)
        {
            if((child.isDirectory() && child.canRead() && child.exists()) == false)
            {
                LOG.warn("ignore path {}, it does not point to a readable exist directory", child.getPath());
                continue;
            }

            String filename = child.getName();
            String[] tokens = filename.split("-");
            if(tokens == null || tokens.length != 2)
            {
                LOG.warn("ignore dir {}, invalid filename syntax", child.getPath());
                continue;
            }

            int slotIndex;
            long slotId;
            try
            {
                slotIndex = Integer.parseInt(tokens[0]);
                slotId = Long.parseLong(tokens[1]);
            }catch(NumberFormatException e)
            {
                LOG.warn("ignore dir {}, invalid filename syntax", child.getPath());
                continue;
            }

            slotIndexIdMap.put(slotIndex, slotId);
        }

        Set<Integer> slotIndexes = slotIndexIdMap.keySet();

        for(Integer slotIndex : slotIndexes)
        {
            try
            {
                P11SlotIdentifier slotId = new P11SlotIdentifier(slotIndex, slotIndexIdMap.get(slotIndex));

                if(moduleConf.isSlotIncluded(slotId) == false)
                {
                    continue;
                }

                File slotDir = new File(baseDir, slotIndex + "-" + slotIndexIdMap.get(slotIndex));
                File[] keystoreFiles = slotDir.listFiles();
                if(keystoreFiles == null || keystoreFiles.length == 0)
                {
                    LOG.info("No key found in directory", slotDir);
                    continue;
                }

                for(File file : keystoreFiles)
                {
                    String fn = file.getName();
                    String keyLabel;
                    KeyStore ks;
                    if(fn.endsWith(".p12") || fn.endsWith(".P12"))
                    {
                        ks = KeyStore.getInstance("PKCS12", "BC");
                        keyLabel= fn.substring(0, fn.length() - ".p12".length());
                    }
                    else if(fn.endsWith(".jks") || fn.endsWith(".JKS"))
                    {
                        ks = KeyStore.getInstance("JKS");
                        keyLabel= fn.substring(0, fn.length() - ".jks".length());
                    }
                    else
                    {
                        LOG.info("Ignore none keystore file {}", file.getPath());
                        continue;
                    }

                    String sha1Fp = IoCertUtil.sha1sum(keyLabel.getBytes("UTF-8"));
                    P11KeyIdentifier keyId = new P11KeyIdentifier(Hex.decode(sha1Fp.substring(0, 16)), keyLabel);
                    List<char[]> password = moduleConf.getPasswordRetriever().getPassword(slotId);
                    if(password == null)
                    {
                        LOG.info("No password is configured");
                        continue;
                    }
                    else if(password.size() != 1)
                    {
                        LOG.info("Exactly 1 password must be specified, but not {}", password.size());
                        continue;
                    }

                    ks.load(new FileInputStream(file), password.get(0));

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
                        LOG.info("No key is contained in file {}, ignore it", fn);
                        continue;
                    }

                    PrivateKey privKey = (PrivateKey) ks.getKey(keyname, password.get(0));

                    if( (privKey instanceof RSAPrivateKey || privKey instanceof DSAPrivateKey ||
                            privKey instanceof ECPrivateKey) == false)
                    {
                        throw new SignerException("Unsupported key " + privKey.getClass().getName());
                    }

                    Set<Certificate> caCerts = new HashSet<>();

                    X509Certificate cert = (X509Certificate) ks.getCertificate(keyname);
                    Certificate[] certsInKeystore = ks.getCertificateChain(keyname);
                    if(certsInKeystore.length > 1)
                    {
                        for(int i = 1; i < certsInKeystore.length; i++)
                        {
                            caCerts.add(certsInKeystore[i]);
                        }
                    }

                    X509Certificate[] certificateChain = IoCertUtil.buildCertPath(cert, caCerts);
                    KeystoreP11Identity p11Identity = new KeystoreP11Identity(slotId,
                            keyId, privKey, certificateChain, 20);
                    currentIdentifies.add(p11Identity);
                }
            }catch(Throwable t)
            {
                final String message = "Could not initialize PKCS11 slot " + slotIndex +
                        " (module: " + moduleConf.getName() + ")";
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                }
                LOG.debug(message, t);
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
            for(KeystoreP11Identity identity : this.identities)
            {
                sb.append("\t(slot ").append(identity.getSlotId());
                sb.append(", algo=").append(identity.getPublicKey().getAlgorithm());
                sb.append(", label=").append(identity.getKeyId().getKeyLabel()).append(")\n");
            }

            LOG.info(sb.toString());
        }
    }
    @Override
    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no key with " + keyId);
        }

        return identity.CKM_RSA_PKCS(encodedDigestInfo);
    }

    @Override
    public byte[] CKM_RSA_X509(byte[] hash, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no key with " + keyId);
        }

        return identity.CKM_RSA_X509(hash);
    }

    @Override
    public byte[] CKM_ECDSA(byte[] hash, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no key with " + keyId);
        }

        return identity.CKM_ECDSA(hash);
    }

    @Override
    public byte[] CKM_DSA(byte[] hash, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no key with " + keyId);
        }

        return identity.CKM_DSA(hash);
    }

    @Override
    public PublicKey getPublicKey(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        return identity == null ? null : identity.getPublicKey();
    }

    @Override
    public X509Certificate getCertificate(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        return identity == null ? null : identity.getCertificate();
    }

    @Override
    public X509Certificate[] getCertificates(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        return identity == null ? null : identity.getCertificateChain();
    }

    @Override
    public P11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException
    {
        List<P11SlotIdentifier> slotIds = new LinkedList<>();
        for(KeystoreP11Identity identity : identities)
        {
            P11SlotIdentifier slotId = identity.getSlotId();
            if(slotIds.contains(slotId) == false)
            {
                slotIds.add(slotId);
            }
        }

        return slotIds.toArray(new P11SlotIdentifier[0]);
    }

    @Override
    public String[] getKeyLabels(P11SlotIdentifier slotId)
    throws SignerException
    {
        List<String> keyLabels = new LinkedList<>();
        for(KeystoreP11Identity identity : identities)
        {
            if(slotId.equals(identity.getSlotId()))
            {
                keyLabels.add(identity.getKeyId().getKeyLabel());
            }
        }

        return keyLabels.toArray(new String[0]);
    }

    private KeystoreP11Identity getIdentity(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        if(keyId.getKeyLabel() == null)
        {
            throw new SignerException("Only key referencing by key-label is supported");
        }

        for(KeystoreP11Identity identity : identities)
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
        return moduleConf.toString();
    }

}
