/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.api.p11.P11SlotIdentifier;

import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 * @author Lijun Liao
 */

@SuppressWarnings("restriction")
public final class SunP11CryptService implements P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(SunP11CryptService.class);

    private final ConcurrentSkipListSet<SunP11Identity> identities =
            new ConcurrentSkipListSet<>();

    private final P11ModuleConf moduleConf;

    private static final Map<String, SunP11CryptService> instances = new HashMap<>();

    public static SunP11CryptService getInstance(
            final P11ModuleConf moduleConf)
    throws SignerException {
        SunNamedCurveExtender.addNamedCurves();

        synchronized (instances) {
            final String name = moduleConf.getName();
            SunP11CryptService instance = instances.get(name);
            if (instance == null) {
                instance = new SunP11CryptService(moduleConf);
                instances.put(name, instance);
            }

            return instance;
        }
    }

    private SunP11CryptService(
            final P11ModuleConf moduleConf)
    throws SignerException {
        ParamUtil.assertNotNull("moduleConf", moduleConf);
        this.moduleConf = moduleConf;

        int idx_sunec = -1;
        int idx_xipki = -1;

        Provider xipkiProv = null;
        Provider[] providers = Security.getProviders();
        int n = providers.length;
        for (int i = 0; i < n; i++) {
            String name = providers[i].getName();
            if ("SunEC".equals(name)) {
                idx_sunec = i;
            } else if (XipkiSunECProvider.NAME.equals(name)) {
                xipkiProv = providers[i];
                idx_xipki = i;
            }
        }

        if (idx_sunec != -1) {
            if (xipkiProv == null) {
                xipkiProv = new XipkiSunECProvider();
                idx_xipki = providers.length;
            } else if (idx_sunec < idx_xipki) {
                Security.removeProvider(XipkiSunECProvider.NAME);
            }

            if (idx_sunec < idx_xipki) {
                Security.insertProviderAt(xipkiProv, idx_sunec + 1);
            }

            providers = Security.getProviders();
            n = providers.length;
            for (int i = 0; i < n; i++) {
                String name = providers[i].getName();
                LOG.info("provider[" + i + "]: " + name);
            }
        }

        refresh();
    }

    @Override
    public synchronized void refresh()
    throws SignerException {
        final String nativeLib = moduleConf.getNativeLibrary();

        Set<SunP11Identity> currentIdentifies = new HashSet<>();

        // try to initialize with the slot 0
        Provider p11ProviderOfSlot0 = getPKCS11Provider(nativeLib, 0);

        long[] slotList = allSlots(nativeLib);

        for (int i = 0; i < slotList.length; i++) {
            P11SlotIdentifier slotId = new P11SlotIdentifier(i, slotList[i]);

            if (!moduleConf.isSlotIncluded(slotId)) {
                continue;
            }

            try {
                Provider provider;
                if (i == 0) {
                    provider = p11ProviderOfSlot0;
                } else {
                    provider = getPKCS11Provider(nativeLib, i);
                }

                KeyStore keystore = KeyStore.getInstance("PKCS11", provider);

                List<char[]> password = moduleConf.getPasswordRetriever().getPassword(slotId);

                for (char[] singlePassword : password) {
                    if (singlePassword == null) { // keystore does not allow empty password
                        singlePassword = "dummy".toCharArray();
                    }
                    try {
                        keystore.load(null, singlePassword);
                    } catch (Exception e) {
                        throw new SignerException(e.getMessage(), e);
                    }
                }

                Enumeration<String> aliases = keystore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    try {
                        if (!keystore.isKeyEntry(alias)) {
                            continue;
                        }

                        char[] keyPwd = null;
                        if (CollectionUtil.isNotEmpty(password)) {
                            keyPwd = password.get(0);
                        }
                        if (keyPwd == null) { // keystore does not allow empty password
                            keyPwd = "dummy".toCharArray();
                        }

                        Key key = keystore.getKey(alias, keyPwd);
                        if (!(key instanceof PrivateKey)) {
                            continue;
                        }

                        SunP11Identity oldIdentity = getIdentity(slotId,
                                new P11KeyIdentifier(alias));
                        if (oldIdentity != null) {
                            currentIdentifies.add(oldIdentity);
                            continue;
                        }

                        PrivateKey signatureKey = (PrivateKey) key;
                        X509Certificate signatureCert =
                                (X509Certificate) keystore.getCertificate(alias);
                        PublicKey pubKey = signatureCert.getPublicKey();

                        Certificate[] certchain = keystore.getCertificateChain(alias);
                        X509Certificate[] x509Certchain = new X509Certificate[certchain.length];
                        for (int j = 0; j < certchain.length; j++) {
                            x509Certchain[j] = (X509Certificate) certchain[j];
                        }

                        if ("EC".equalsIgnoreCase(pubKey.getAlgorithm())) {
                            if (!(pubKey instanceof ECPublicKey)) {
                                // reparse the certificate due to bug in bcprov version 1.49
                                // signatureCert = X509Util.parseCert(signatureCert.getEncoded());
                                pubKey = signatureCert.getPublicKey();
                            }
                        }

                        SunP11Identity p11Identity = new SunP11Identity(provider, slotId, alias,
                                signatureKey, x509Certchain, pubKey);
                        currentIdentifies.add(p11Identity);
                    } catch (SignerException e) {
                        String msg = "SignerException while constructing SunP11Identity for alias "
                                + alias + " (slot: " + i + ", module: " + moduleConf.getName()
                                + ")";
                        LOG.warn(msg + ", message: {}", e.getMessage());
                        LOG.debug(msg, e);
                        continue;
                    }
                }
            } catch (Throwable t) {
                final String message = "could not initialize PKCS11 slot " + i + " (module: "
                        + moduleConf.getName() + ")";
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                            t.getMessage());
                }
                LOG.debug(message, t);
                continue;
            }
        }

        this.identities.clear();
        this.identities.addAll(currentIdentifies);
        currentIdentifies.clear();
        currentIdentifies = null;

        if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("Initialized ").append(this.identities.size()).append(" PKCS#11 Keys:\n");
            for (SunP11Identity identity : this.identities) {
                sb.append("\t(slot ").append(identity.getSlotId());
                sb.append(", algo=").append(identity.getPublicKey().getAlgorithm());
                sb.append(", label=").append(identity.getKeyLabel()).append(")\n");
            }

            LOG.info(sb.toString());
        }
    }

    @Override
    public byte[] CKM_RSA_PKCS(
            final byte[] encodedDigestInfo,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        ensureResource();

        SunP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_RSA_PKCS(encodedDigestInfo);
    }

    @Override
    public byte[] CKM_RSA_X509(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        ensureResource();

        SunP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_RSA_X509(hash);
    }

    @Override
    public byte[] CKM_ECDSA_Plain(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        ensureResource();

        SunP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_ECDSA(hash);
    }

    @Override
    public byte[] CKM_ECDSA_X962(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        ensureResource();

        SunP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }
        return identity.CKM_ECDSA_X962(hash);
    }

    @Override
    public byte[] CKM_DSA_Plain(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        ensureResource();

        SunP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_DSA(hash);
    }

    @Override
    public byte[] CKM_DSA_X962(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        ensureResource();

        SunP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_DSA_X962(hash);
    }

    @Override
    public PublicKey getPublicKey(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        SunP11Identity identity = getIdentity(slotId, keyId);
        return (identity == null)
                ? null
                : identity.getPublicKey();
    }

    @Override
    public X509Certificate getCertificate(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        SunP11Identity identity = getIdentity(slotId, keyId);
        return (identity == null)
                ? null
                : identity.getCertificate();
    }

    private SunP11Identity getIdentity(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        if (keyId.getKeyLabel() == null) {
            throw new SignerException("only key referencing by key-label is supported");
        }

        for (SunP11Identity identity : identities) {
            if (identity.match(slotId, keyId.getKeyLabel())) {
                return identity;
            }
        }

        return null;
    }

    @Override
    public String toString() {
        return moduleConf.toString();
    }

    @Override
    public X509Certificate[] getCertificates(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        SunP11Identity identity = getIdentity(slotId, keyId);
        return (identity == null)
                ? null
                : identity.getCertificateChain();
    }

    @Override
    public P11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException {
        List<P11SlotIdentifier> slotIds = new LinkedList<>();
        for (SunP11Identity identity : identities) {
            P11SlotIdentifier slotId = identity.getSlotId();
            if (!slotIds.contains(slotId)) {
                slotIds.add(slotId);
            }
        }

        return slotIds.toArray(new P11SlotIdentifier[0]);
    }

    @Override
    public String[] getKeyLabels(
            final P11SlotIdentifier slotId)
    throws SignerException {
        List<String> keyLabels = new LinkedList<>();
        for (SunP11Identity identity : identities) {
            if (slotId.equals(identity.getSlotId())) {
                keyLabels.add(identity.getKeyLabel());
            }
        }

        return keyLabels.toArray(new String[0]);
    }

    private synchronized void ensureResource() {
    }

    private static Provider getPKCS11Provider(
            final String pkcs11Module,
            final int slotIndex) {
        File f = new File(pkcs11Module);

        StringBuilder sb = new StringBuilder();
        sb.append("Slot-").append(slotIndex);
        sb.append("_Lib-").append(f.getName());

        String name = sb.toString();

        Provider p = Security.getProvider("SunPKCS11-" + name);
        if (p != null) {
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

    private static long[] allSlots(
            final String pkcs11Module)
    throws SignerException {
        String functionList = null;
        sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS pInitArgs = null;
        boolean omitInitialize = true;

        sun.security.pkcs11.wrapper.PKCS11 pkcs11;
        try {
            pkcs11 = sun.security.pkcs11.wrapper.PKCS11.getInstance(
                    pkcs11Module, functionList, pInitArgs, omitInitialize);
        } catch (IOException | PKCS11Exception e) {
            throw new SignerException(e.getClass().getName() + ": " + e.getMessage(), e);
        }

        long[] slotList;
        try {
            slotList = pkcs11.C_GetSlotList(false);
        } catch (PKCS11Exception e) {
            throw new SignerException("PKCS11Exception: " + e.getMessage(), e);
        }
        return slotList;
    }

}
