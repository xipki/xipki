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

package org.xipki.commons.security.impl.p11.keystore;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
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
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11MechanismRetriever;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.parameters.P11Params;

import iaik.pkcs.pkcs11.wrapper.PKCS11RuntimeException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeystoreP11CryptService implements P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11CryptService.class);

    private static final Map<String, KeystoreP11CryptService> INSTANCES = new HashMap<>();

    private final P11ModuleConf moduleConf;

    private final ConcurrentSkipListSet<KeystoreP11Identity> identities
            = new ConcurrentSkipListSet<>();

    private KeystoreP11Module module;

    private final Map<Integer, Set<Long>> slotIndexMechanismsMap = new ConcurrentHashMap<>();

    private final Map<Long, Set<Long>> slotIdMechanismsMap = new ConcurrentHashMap<>();

    public KeystoreP11CryptService(
            final P11ModuleConf moduleConf)
    throws SignerException {
        this.moduleConf = ParamUtil.requireNonNull("moduleConf", moduleConf);
        refresh();
    }

    @Override
    public synchronized void refresh()
    throws SignerException {
        LOG.info("Refreshing PKCS#11 module {}", moduleConf.getName());
        try {
            this.module = KeystoreP11ModulePool.getInstance().getModule(moduleConf);
        } catch (SignerException ex) {
            final String message = "could not initialize the PKCS#11 Module for "
                    + moduleConf.getName();
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            throw ex;
        }

        Set<KeystoreP11Identity> currentIdentifies = new HashSet<>();
        Map<P11SlotIdentifier, Set<Long>> currentSupportedMechanisms = new HashMap<>();
        P11MechanismRetriever mechRetriever = moduleConf.getP11MechanismRetriever();

        List<P11SlotIdentifier> slotIds = module.getSlotIdentifiers();
        for (P11SlotIdentifier slotId : slotIds) {
            KeystoreP11Slot slot;
            try {
                slot = module.getSlot(slotId);
                if (slot == null) {
                    LOG.warn("could not initialize slot " + slotId);
                    continue;
                }
                slot.refresh();
            } catch (SignerException ex) {
                final String message = "SignerException while initializing slot " + slotId;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
                continue;
            } catch (Throwable th) {
                final String message = "unexpected error while initializing slot " + slotId;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), th.getClass().getName(),
                            th.getMessage());
                }
                LOG.debug(message, th);
                continue;
            }

            Set<Long> mechs = slot.getSupportedMechanisms();
            Set<Long> mechs2 = new HashSet<>();
            for (Long mech : mechs) {
                if (mechRetriever.isMechanismPermitted(slotId, mech)) {
                    mechs2.add(mech);
                }
            }

            LOG.info("slot {} in module {} supports following mechanisms: {}", slotId,
                    moduleConf.getName(), mechs2);
            currentSupportedMechanisms.put(slotId, mechs2);

            for (P11Identity identity : slot.getP11Identities()) {
                currentIdentifies.add((KeystoreP11Identity) identity);
            } // end for
        } // end for

        this.identities.clear();
        for (KeystoreP11Identity identity : currentIdentifies) {
            this.identities.add(identity);
        }
        currentIdentifies.clear();
        currentIdentifies = null;

        this.slotIndexMechanismsMap.clear();
        this.slotIdMechanismsMap.clear();
        for (P11SlotIdentifier slotId : currentSupportedMechanisms.keySet()) {
            Set<Long> mechs = Collections.unmodifiableSet(currentSupportedMechanisms.get(slotId));
            this.slotIdMechanismsMap.put(slotId.getSlotId(), mechs);
            this.slotIndexMechanismsMap.put(slotId.getSlotIndex(), mechs);
        }
        currentSupportedMechanisms = null;

        if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("initialized ").append(this.identities.size()).append(" PKCS#11 Keys:\n");
            for (KeystoreP11Identity identity : this.identities) {
                sb.append("\t(").append(identity.getEntityId());
                sb.append(", algo=").append(identity.getPublicKey().getAlgorithm()).append(")\n");
            }

            LOG.info(sb.toString());
        }

        LOG.info("refreshed PKCS#11 module {}", moduleConf.getName());
    } // method refresh

    @Override
    public byte[] sign(
            final P11EntityIdentifier entityId,
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws SignerException {
        if (!supportsMechanism(entityId.getSlotId(), mechanism)) {
            throw new SignerException("mechanism " + mechanism + " is not supported by slot"
                    + entityId.getSlotId());
        }

        try {
            return getNonNullIdentity(entityId).sign(mechanism, parameters, content);
        } catch (PKCS11RuntimeException ex) {
            final String message = "could not call identity.sign()";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            throw new SignerException("PKCS11RuntimeException: " + ex.getMessage(), ex);
        }
    }

    @Override
    public PublicKey getPublicKey(
            final P11EntityIdentifier entityId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(entityId);
        return (identity == null)
                ? null
                : identity.getPublicKey();
    }

    @Override
    public X509Certificate getCertificate(
            final P11EntityIdentifier entityId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(entityId);
        return (identity == null)
                ? null
                : identity.getCertificate();
    }

    @Override
    public X509Certificate[] getCertificates(
            final P11EntityIdentifier entityId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(entityId);
        return (identity == null)
                ? null
                : identity.getCertificateChain();
    }

    @Override
    public P11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException {
        List<P11SlotIdentifier> slotIds = new LinkedList<>();
        for (KeystoreP11Identity identity : identities) {
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
    throws SignerException {
        List<String> keyLabels = new LinkedList<>();
        for (KeystoreP11Identity identity : identities) {
            if (slotId.equals(identity.getEntityId().getSlotId())) {
                keyLabels.add(identity.getEntityId().getKeyId().getKeyLabel());
            }
        }

        return keyLabels.toArray(new String[0]);
    }

    private KeystoreP11Identity getNonNullIdentity(
            final P11EntityIdentifier entityId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(entityId);
        if (identity == null) {
            throw new SignerException("found no key with " + entityId);
        }
        return identity;
    }

    private KeystoreP11Identity getIdentity(
            final P11EntityIdentifier entityId)
    throws SignerException {
        ParamUtil.requireNonNull("entityId", entityId);

        for (KeystoreP11Identity identity : identities) {
            if (identity.match(entityId)) {
                return identity;
            }
        }

        return null;
    }

    @Override
    public String toString() {
        return moduleConf.toString();
    }

    public static KeystoreP11CryptService getInstance(
            final P11ModuleConf moduleConf)
    throws SignerException {
        ParamUtil.requireNonNull("moduleConf", moduleConf);
        synchronized (INSTANCES) {
            final String name = moduleConf.getName();
            KeystoreP11CryptService instance = INSTANCES.get(name);
            if (instance == null) {
                instance = new KeystoreP11CryptService(moduleConf);
                INSTANCES.put(name, instance);
            }

            return instance;
        }
    }

    @Override
    public boolean supportsMechanism(
            final P11SlotIdentifier slotId,
            final long mechanism) {
        // FIXME: consider moduleName
        Set<Long> mechs = null;
        if (slotId.getSlotId() != null) {
            mechs = slotIdMechanismsMap.get(slotId.getSlotId());
        } else if (slotId.getSlotIndex() != null) {
            mechs = slotIndexMechanismsMap.get(slotId.getSlotIndex());
        }
        return mechs == null
                ? false
                : mechs.contains(mechanism);
    }

}
