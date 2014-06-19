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

package org.xipki.security.p11.iaik;

import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11RuntimeException;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
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
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public final class IaikP11CryptService implements P11CryptService
{
    private static final Logger LOG = LoggerFactory.getLogger(IaikP11CryptService.class);
    private static final long MIN_RECONNECT_INTERVAL = 60L * 1000;

    private final ConcurrentSkipListSet<IaikP11Identity> identities = new ConcurrentSkipListSet<>();

    private IaikExtendedModule extModule;

    private String pkcs11Module;
    private String pkcs11ModuleOmitSensitiveInfo;
    private char[] password;
    private Set<Integer> includeSlotIndexes;
    private Set<Integer> excludeSlotIndexes;

    private static final Map<String, IaikP11CryptService> instances = new HashMap<>();

    public synchronized static IaikP11CryptService getInstance(String pkcs11Module, char[] password)
    throws SignerException
    {
        return getInstance(pkcs11Module, password, null, null);
    }

    public synchronized static IaikP11CryptService getInstance(String pkcs11Module, char[] password,
            Set<Integer> includeSlotIndexes, Set<Integer> excludeSlotIndexes)
    throws SignerException
    {
        synchronized (instances)
        {
            IaikP11CryptService instance = instances.get(pkcs11Module);
            if(instance == null)
            {
                instance = new IaikP11CryptService(pkcs11Module, password, includeSlotIndexes, excludeSlotIndexes);
                instances.put(pkcs11Module, instance);
            }

            return instance;
        }
    }

    private IaikP11CryptService(String pkcs11Module, char[] password,
            Set<Integer> includeSlotIndexes, Set<Integer> excludeSlotIndexes)
    throws SignerException
    {
        ParamChecker.assertNotEmpty("pkcs11Module", pkcs11Module);
        this.pkcs11Module = pkcs11Module;
        this.pkcs11ModuleOmitSensitiveInfo = IaikP11Util.eraseSensitiveInfo(pkcs11Module);
        this.password = (password == null) ? "dummy".toCharArray() : password;
        this.includeSlotIndexes = includeSlotIndexes == null ?
                null : new HashSet<>(includeSlotIndexes);
        this.excludeSlotIndexes = excludeSlotIndexes == null ?
                null : new HashSet<>(excludeSlotIndexes);
        refresh();
    }

    private boolean lastRefreshSuccessfull;
    private long lastRefresh;
    private synchronized boolean reconnect()
    throws SignerException
    {
        if(System.currentTimeMillis() - lastRefresh < MIN_RECONNECT_INTERVAL)
        {
            LOG.info("Just refreshed within one minute, skip this reconnect()");
            return lastRefreshSuccessfull;
        }

        lastRefresh = System.currentTimeMillis();

        IaikP11ModulePool.getInstance().removeModule(pkcs11Module);
        refresh();
        return lastRefreshSuccessfull;
    }

    @Override
    public synchronized void refresh()
    throws SignerException
    {
        LOG.info("Refreshing PKCS#11 module {}", pkcs11ModuleOmitSensitiveInfo);
        lastRefreshSuccessfull = false;
        try
        {
            this.extModule = IaikP11ModulePool.getInstance().getModule(pkcs11Module);
        }catch(SignerException e)
        {
            LOG.error("Could not initialize the PKCS#11 Module for {}: SignerException: {}",
                    pkcs11ModuleOmitSensitiveInfo, e.getMessage());
            LOG.debug("Could not initialize the PKCS#11 Module for " + pkcs11ModuleOmitSensitiveInfo, e);
            throw e;
        }

        Map<String, Set<X509Certificate>> allCerts = new HashMap<>();

        Set<IaikP11Identity> currentIdentifies = new HashSet<>();

        Set<PKCS11SlotIdentifier> slotIds = extModule.getAllSlotIds();
        for(PKCS11SlotIdentifier slotId : slotIds)
        {
            if(excludeSlotIndexes != null && excludeSlotIndexes.contains(slotId.getSlotIndex()))
            {
                continue;
            }

            if(includeSlotIndexes != null && includeSlotIndexes.contains(slotId.getSlotIndex()) == false)
            {
                continue;
            }

            IaikExtendedSlot slot;
            try
            {
                slot = extModule.getSlot(slotId, password);
                if(slot == null)
                {
                    LOG.warn("Could not initialize slot " + slotId);
                    continue;
                }
            } catch (SignerException e)
            {
                LOG.warn("SignerException while initializing slot {}, message: {}", slotId, e.getMessage());
                LOG.debug("SignerException while initializing slot " + slotId, e);
                continue;
            } catch (Throwable t)
            {
                LOG.warn("unexpected error while initializing slot {}, message: {}", slotId, t.getMessage());
                LOG.debug("unexpected error while initializing slot " + slotId, t);
                continue;
            }

            List<PrivateKey> signatureKeys = slot.getAllPrivateObjects(Boolean.TRUE, null);
            for(PrivateKey signatureKey : signatureKeys)
            {
                byte[] keyId = signatureKey.getId().getByteArrayValue();
                if(keyId == null || keyId.length == 0)
                {
                    continue;
                }

                try
                {
                    X509PublicKeyCertificate certificateObject = slot.getCertificateObject(keyId, null);

                    X509Certificate signatureCert = null;
                    PublicKey signaturePublicKey = null;

                    if(certificateObject != null)
                    {
                        byte[] encoded = certificateObject.getValue().getByteArrayValue();
                        try
                        {
                            signatureCert = (X509Certificate) IoCertUtil.parseCert(
                                        new ByteArrayInputStream(encoded));
                        } catch (Exception e)
                        {
                            String keyIdStr = hex(keyId);
                            LOG.warn("Could not parse certificate with id {}, message: {}", keyIdStr, e.getMessage());
                            LOG.debug("Could not parse certificate with id " + keyIdStr, e);
                            continue;
                        }
                        signaturePublicKey = signatureCert.getPublicKey();
                    }
                    else
                    {
                        signatureCert = null;
                        iaik.pkcs.pkcs11.objects.PublicKey publicKeyObject = slot.getPublicKeyObject(
                                Boolean.TRUE, null, keyId, null);
                        if(publicKeyObject == null)
                        {
                            String msg = "neither certificate nor public key for signing is available";
                            LOG.warn(msg);
                            continue;
                        }

                        signaturePublicKey = generatePublicKey(publicKeyObject);
                    }

                    List<X509Certificate> certChain = new LinkedList<>();

                    if(signatureCert != null)
                    {
                        certChain.add(signatureCert);
                        while(true)
                        {
                            X509Certificate context = certChain.get(certChain.size() - 1);
                            if(IoCertUtil.isSelfSigned(context))
                            {
                                break;
                            }

                            String issuerSubject = signatureCert.getIssuerX500Principal().getName();
                            Set<X509Certificate> issuerCerts = allCerts.get(issuerSubject);
                            if(issuerCerts == null)
                            {
                                issuerCerts = new HashSet<>();
                                X509PublicKeyCertificate[] certObjects = slot.getCertificateObjects(
                                        signatureCert.getIssuerX500Principal());
                                if(certObjects != null && certObjects.length > 0)
                                {
                                    for(X509PublicKeyCertificate certObject : certObjects)
                                    {
                                        issuerCerts.add(IoCertUtil.parseCert(certObject.getValue().getByteArrayValue()));
                                    }
                                }

                                if(issuerCerts.isEmpty() == false)
                                {
                                    allCerts.put(issuerSubject, issuerCerts);
                                }
                            }

                            if(issuerCerts == null || issuerCerts.isEmpty())
                            {
                                break;
                            }

                            // find the certificate
                            for(X509Certificate issuerCert : issuerCerts)
                            {
                                try
                                {
                                    context.verify(issuerCert.getPublicKey());
                                    certChain.add(issuerCert);
                                }catch(Exception e)
                                {
                                }
                            }
                        }
                    }

                    Pkcs11KeyIdentifier tKeyId = new Pkcs11KeyIdentifier(
                            signatureKey.getId().getByteArrayValue(),
                            new String(signatureKey.getLabel().getCharArrayValue()));

                    IaikP11Identity identity = new IaikP11Identity(slotId, tKeyId,
                            certChain.toArray(new X509Certificate[0]), signaturePublicKey);
                    currentIdentifies.add(identity);
                } catch (SignerException e)
                {
                    String keyIdStr = hex(keyId);
                    LOG.warn("SignerException while initializing key with key-id {}, message: {}",
                            keyIdStr, e.getMessage());
                    LOG.debug("SignerException while initializing key with key-id " + keyIdStr, e);
                    continue;
                } catch (Throwable t)
                {
                    String keyIdStr = hex(keyId);
                    LOG.warn("Unexpected exception while initializing key with key-id {}, message: {}",
                            keyIdStr, t.getMessage());
                    LOG.debug("Unexpected exception while initializing key with key-id " + keyIdStr, t);
                    continue;
                }
            }
        }

        this.identities.clear();
        this.identities.addAll(currentIdentifies);
        currentIdentifies.clear();
        currentIdentifies = null;

        lastRefreshSuccessfull = true;

        if(LOG.isInfoEnabled())
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Initialized ").append(this.identities.size()).append(" PKCS#11 Keys:\n");
            for(IaikP11Identity identity : this.identities)
            {
                sb.append("\t(slot ").append(identity.getSlotId());
                sb.append(", algo=").append(identity.getPublicKey().getAlgorithm());
                sb.append(", key=").append(identity.getKeyId()).append(")\n");
            }

            LOG.info(sb.toString());
        }

        LOG.info("Refreshed PKCS#11 module {}", pkcs11ModuleOmitSensitiveInfo);
    }

    @Override
    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo, PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        checkState();

        IaikP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no identity with " + keyId + " in slot " + slotId);
        }

        try
        {
            return identity.CKM_RSA_PKCS(extModule, password, encodedDigestInfo);
        }catch(PKCS11RuntimeException pre)
        {
            LOG.warn("PKCS11RuntimeException: {}", pre.getMessage());
            LOG.debug("PKCS11RuntimeException", pre);
            if(reconnect())
            {
                return CKM_RSA_PKCS_noReconnect(encodedDigestInfo, slotId, keyId);
            }
            else
            {
                throw new SignerException("PKCS11RuntimeException: " + pre.getMessage(), pre);
            }
        }
    }

    private byte[] CKM_RSA_PKCS_noReconnect(byte[] encodedDigestInfo, PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        IaikP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no identity with " + keyId + " in slot " + slotId);
        }

        return identity.CKM_RSA_PKCS(extModule, password, encodedDigestInfo);
    }

    @Override
    public byte[] CKM_RSA_X509(byte[] hash, PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        checkState();

        IaikP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no identity with " + keyId + " in slot " + slotId);
        }

        try
        {
            return identity.CKM_RSA_X_509(extModule, password, hash);
        }catch(PKCS11RuntimeException pre)
        {
            LOG.warn("PKCS11RuntimeException: {}", pre.getMessage());
            LOG.debug("PKCS11RuntimeException", pre);
            if(reconnect())
            {
                return CKM_RSA_X509_noReconnect(hash, slotId, keyId);
            }
            else
            {
                throw new SignerException("PKCS11RuntimeException: " + pre.getMessage(), pre);
            }
        }
    }

    private byte[] CKM_RSA_X509_noReconnect(byte[] hash, PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        IaikP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no identity with " + keyId + " in slot " + slotId);
        }

        return identity.CKM_RSA_X_509(extModule, password, hash);
    }

    @Override
    public byte[] CKM_ECDSA(byte[] hash, PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        checkState();

        IaikP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no identity with " + keyId + " in slot " + slotId);
        }

        try
        {
            return identity.CKM_ECDSA(extModule, password, hash);
        }catch(PKCS11RuntimeException pre)
        {
            LOG.warn("PKCS11RuntimeException: {}", pre.getMessage());
            LOG.debug("PKCS11RuntimeException", pre);
            if(reconnect())
            {
                return CKM_ECDSA_noReconnect(hash, slotId, keyId);
            }
            else
            {
                throw new SignerException("PKCS11RuntimeException: " + pre.getMessage(), pre);
            }
        }
    }

    private byte[] CKM_ECDSA_noReconnect(byte[] hash, PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        IaikP11Identity identity = getIdentity(slotId, keyId);
        if(identity == null)
        {
            throw new SignerException("Found no identity with " + keyId + " in slot " + slotId);
        }

        return identity.CKM_ECDSA(extModule, password, hash);
    }

    @Override
    public PublicKey getPublicKey(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        IaikP11Identity identity = getIdentity(slotId, keyId);
        return identity == null ? null : identity.getPublicKey();
    }

    @Override
    public X509Certificate getCertificate(PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        IaikP11Identity identity = getIdentity(slotId, keyId);
        return identity == null ? null : identity.getCertificate();
    }

    private IaikP11Identity getIdentity(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    {
        for(IaikP11Identity identity : identities)
        {
            if(identity.match(slotId, keyId))
            {
                return identity;
            }
        }

        return null;
    }

    private synchronized void checkState()
    throws SignerException
    {
        if(lastRefreshSuccessfull == false)
        {
            if(System.currentTimeMillis() - lastRefresh >= MIN_RECONNECT_INTERVAL)
            {
                reconnect();
            }
        }

        if(lastRefreshSuccessfull == false)
        {
            throw new SignerException("PKCS#11 module is not initialized");
        }
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("IaikP11CryptService\n");
        sb.append("\tModule: ").append(pkcs11ModuleOmitSensitiveInfo).append("\n");
        return sb.toString();
    }

    private static String hex(byte[] bytes)
    {
        return Hex.toHexString(bytes).toUpperCase();
    }

    private static PublicKey generatePublicKey(iaik.pkcs.pkcs11.objects.PublicKey p11Key)
    throws SignerException
    {
        if(p11Key instanceof RSAPublicKey)
        {
            RSAPublicKey rsaP11Key = (RSAPublicKey) p11Key;
            byte[] expBytes = rsaP11Key.getPublicExponent().getByteArrayValue();
            BigInteger exp = new BigInteger(1,expBytes);

            byte[] modBytes = rsaP11Key.getModulus().getByteArrayValue();
            BigInteger mod = new BigInteger(1,modBytes);

            if(LOG.isDebugEnabled())
            {
                LOG.debug("Modulus:\n {}", Hex.toHexString(modBytes));
            }
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod,exp);
            try
            {
                KeyFactory keyFactory=KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(keySpec);
            }catch(NoSuchAlgorithmException e)
            {
                throw new SignerException(e);
            } catch (InvalidKeySpecException e)
            {
                throw new SignerException(e);
            }
        }
        else if(p11Key instanceof ECDSAPublicKey)
        {
            // FIXME: implement me
            return null;
        }
        else
        {
            throw new SignerException("Unknown public key class " + p11Key.getClass().getName());
        }
    }

    @Override
    public X509Certificate[] getCertificates(PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        IaikP11Identity identity = getIdentity(slotId, keyId);
        return identity == null ? null : identity.getCertificateChain();
    }

    @Override
    public PKCS11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException
    {
        List<PKCS11SlotIdentifier> slotIds = new LinkedList<>();
        for(IaikP11Identity identity : identities)
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
        for(IaikP11Identity identity : identities)
        {
            if(slotId.equals(identity.getSlotId()))
            {
                keyLabels.add(identity.getKeyId().getKeyLabel());
            }
        }

        return keyLabels.toArray(new String[0]);
    }

}
