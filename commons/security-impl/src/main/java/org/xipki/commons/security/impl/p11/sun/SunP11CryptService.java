/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.commons.security.impl.p11.sun;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.CompareUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnknownEntityException;
import org.xipki.commons.security.api.p11.parameters.P11Params;

// CHECKSTYLE:OFF
import sun.security.pkcs11.wrapper.PKCS11Exception;
// CHECKSTYLE:ON

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@SuppressWarnings("restriction")
public final class SunP11CryptService implements P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(SunP11CryptService.class);

    private static final Map<String, SunP11CryptService> INSTANCES = new HashMap<>();

    private final ConcurrentSkipListSet<SunP11Identity> identities =
            new ConcurrentSkipListSet<>();

    private final P11ModuleConf moduleConf;

    private final ConcurrentHashMap<P11SlotIdentifier, SunP11Slot> slotMap
            = new ConcurrentHashMap<>();

    private SunP11CryptService(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        this.moduleConf = ParamUtil.requireNonNull("moduleConf", moduleConf);
        if (moduleConf.getUserType() != P11Constants.CKU_USER) {
            throw new P11TokenException("unsupported userType " + moduleConf.getUserType());
        }
        refresh();
    } // constructor

    @Override
    public synchronized void refresh()
    throws P11TokenException {
        final String nativeLib = moduleConf.getNativeLibrary();

        Set<SunP11Identity> currentIdentifies = new HashSet<>();

        // try to initialize with the slot 0
        Provider p11ProviderOfSlot0 = getPkcs11Provider(nativeLib, 0);

        long[] slotList = allSlots(nativeLib);

        P11MechanismFilter mechanismFilter = moduleConf.getP11MechanismFilter();

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
                    provider = getPkcs11Provider(nativeLib, i);
                }

                SunP11Slot slot = new SunP11Slot(moduleConf.getName(), slotId, mechanismFilter,
                        provider);
                this.slotMap.put(slotId, slot);

                KeyStore keystore = KeyStore.getInstance("PKCS11", provider);
                List<char[]> password = moduleConf.getPasswordRetriever().getPassword(slotId);

                for (char[] singlePassword : password) {
                    try {
                        keystore.load(null,
                            (singlePassword == null)
                                ? "dummy".toCharArray() // keystore does not allow empty password
                                : singlePassword);
                    } catch (Exception ex) {
                        throw new SecurityException(ex.getMessage(), ex);
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
                        if (CollectionUtil.isNonEmpty(password)) {
                            keyPwd = password.get(0);
                        }
                        if (keyPwd == null) { // keystore does not allow empty password
                            keyPwd = "dummy".toCharArray();
                        }

                        Key key = keystore.getKey(alias, keyPwd);
                        if (!(key instanceof PrivateKey)) {
                            continue;
                        }

                        P11EntityIdentifier entityId = new P11EntityIdentifier(slotId,
                                new P11KeyIdentifier(alias));
                        SunP11Identity oldIdentity = getIdentity(entityId);
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

                        SecureRandom random4Sign = moduleConf.getSecurityFactory().getRandom4Sign();
                        SunP11Identity p11Identity = new SunP11Identity(provider, entityId,
                                moduleConf.getMaxMessageSize(), signatureKey, x509Certchain, pubKey,
                                random4Sign);
                        currentIdentifies.add(p11Identity);
                    } catch (SecurityException ex) {
                        String msg = "SignerException while constructing SunP11Identity for alias "
                                + alias + " (slot: " + i + ", module: " + moduleConf.getName()
                                + ")";
                        LOG.warn(msg + ", message: {}", ex.getMessage());
                        LOG.debug(msg, ex);
                        continue;
                    }
                } // end while
            } catch (Throwable th) {
                final String message = "could not initialize PKCS11 slot " + i + " (module: "
                        + moduleConf.getName() + ")";
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), th.getClass().getName(),
                            th.getMessage());
                }
                LOG.debug(message, th);
                continue;
            }
        } // end for(i)

        this.identities.clear();
        this.identities.addAll(currentIdentifies);
        currentIdentifies.clear();
        currentIdentifies = null;

        if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("Initialized ").append(this.identities.size()).append(" PKCS#11 Keys:\n");
            for (SunP11Identity identity : this.identities) {
                sb.append("\t(").append(identity.getEntityId());
                sb.append(", algo=").append(identity.getPublicKey().getAlgorithm()).append(")\n");
            }

            LOG.info(sb.toString());
        }
    } // method refresh

    @Override
    public Set<Long> getSupportedMechanisms(
            final P11SlotIdentifier slotId)
    throws P11TokenException {
        return getNonnullSlot(slotId).getSupportedMechanisms();
    }

    @Override
    public boolean supportsMechanism(
            final P11SlotIdentifier slotId,
            final long mechanism)
    throws P11UnknownEntityException {
        return getNonnullSlot(slotId).supportsMechanism(mechanism);
    }

    private SunP11Slot getNonnullSlot(
            final P11SlotIdentifier slotId)
    throws P11UnknownEntityException {
        SunP11Slot slot = null;
        for (P11SlotIdentifier id : slotMap.keySet()) {
            if (CompareUtil.equalsObject(id.getSlotIndex(), slotId.getSlotIndex())
                    || CompareUtil.equalsObject(id.getSlotId(), slotId.getSlotId())) {
                slot = slotMap.get(id);
                break;
            }
        }

        if (slot == null) {
            throw new P11UnknownEntityException(slotId);
        }
        return slot;
    }

    @Override
    public byte[] sign(
            final P11EntityIdentifier entityId,
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws P11TokenException, SecurityException {
        if (!supportsMechanism(entityId.getSlotId(), mechanism)) {
            throw new SecurityException("mechanism " + mechanism + " is not supported by slot"
                    + entityId.getSlotId());
        }

        ensureResource();
        return getNonnullIdentity(entityId).sign(mechanism, parameters, content);
    }

    @Override
    public PublicKey getPublicKey(
            final P11EntityIdentifier entityId)
    throws P11TokenException {
        return getNonnullIdentity(entityId).getPublicKey();
    }

    @Override
    public X509Certificate getCertificate(
            final P11EntityIdentifier entityId)
    throws P11TokenException {
        return getNonnullIdentity(entityId).getCertificate();
    }

    private SunP11Identity getNonnullIdentity(
            final P11EntityIdentifier entityId)
    throws P11UnknownEntityException {
        SunP11Identity identity = getIdentity(entityId);
        if (identity == null) {
            throw new P11UnknownEntityException(entityId);
        }
        return identity;
    }

    private SunP11Identity getIdentity(
            final P11EntityIdentifier entityId)
    throws P11UnknownEntityException {
        ParamUtil.requireNonNull("entityId", entityId);
        for (SunP11Identity id : identities) {
            if (id.match(entityId)) {
                return id;
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
            final P11EntityIdentifier entityId)
    throws P11TokenException {
        return getNonnullIdentity(entityId).getCertificateChain();
    }

    @Override
    public P11SlotIdentifier[] getSlotIdentifiers()
    throws P11TokenException {
        List<P11SlotIdentifier> slotIds = new LinkedList<>();
        for (SunP11Identity identity : identities) {
            P11SlotIdentifier slotId = identity.getEntityId().getSlotId();
            if (!slotIds.contains(slotId)) {
                slotIds.add(slotId);
            }
        }

        return slotIds.toArray(new P11SlotIdentifier[0]);
    }

    @Override
    public String[] getKeyLabels(
            final P11SlotIdentifier slotId)
    throws P11TokenException {
        List<String> keyLabels = new LinkedList<>();
        for (SunP11Identity identity : identities) {
            if (slotId.equals(identity.getEntityId().getSlotId())) {
                keyLabels.add(identity.getEntityId().getKeyId().getKeyLabel());
            }
        }

        return keyLabels.toArray(new String[0]);
    }

    private synchronized void ensureResource() {
    }

    private static Provider getPkcs11Provider(
            final String pkcs11Module,
            final int slotIndex) {
        File file = new File(pkcs11Module);

        StringBuilder sb = new StringBuilder();
        sb.append("Slot-").append(slotIndex);
        sb.append("_Lib-").append(file.getName());

        String name = sb.toString();

        Provider provider = Security.getProvider("SunPKCS11-" + name);
        if (provider != null) {
            return provider;
        }

        sb = new StringBuilder();
        sb.append("name = ").append(name).append("\n");
        sb.append("slotListIndex = ").append(slotIndex).append("\n");

        sb.append("library = ").append(pkcs11Module).append("\n");

        byte[] pkcs11configBytes = sb.toString().getBytes();

        ByteArrayInputStream configStream = new ByteArrayInputStream(pkcs11configBytes);
        provider = new sun.security.pkcs11.SunPKCS11(configStream);
        Security.addProvider(provider);

        return provider;
    }

    private static long[] allSlots(
            final String pkcs11Module)
    throws P11TokenException {
        String functionList = null;
        sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS initArgs = null;
        boolean omitInitialize = true;

        sun.security.pkcs11.wrapper.PKCS11 pkcs11;
        try {
            pkcs11 = sun.security.pkcs11.wrapper.PKCS11.getInstance(
                    pkcs11Module, functionList, initArgs, omitInitialize);
        } catch (IOException | PKCS11Exception ex) {
            throw new P11TokenException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }

        long[] slotList;
        try {
            slotList = pkcs11.C_GetSlotList(false);
        } catch (PKCS11Exception ex) {
            throw new P11TokenException("PKCS11Exception: " + ex.getMessage(), ex);
        }
        return slotList;
    }

    public static SunP11CryptService getInstance(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        final String name = moduleConf.getName();
        SunP11CryptService instance;

        synchronized (INSTANCES) {
            instance = INSTANCES.get(name);
            if (instance == null) {
                instance = new SunP11CryptService(moduleConf);
                INSTANCES.put(name, instance);
            }
        }

        return instance;
    }

}
