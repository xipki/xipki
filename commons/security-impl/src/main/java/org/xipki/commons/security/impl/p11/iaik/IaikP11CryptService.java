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

package org.xipki.commons.security.impl.p11.iaik;

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

public final class IaikP11CryptService implements P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(IaikP11CryptService.class);

    private static final long MIN_RECONNECT_INTERVAL = 60L * 1000;

    private static final Map<String, IaikP11CryptService> INSTANCES = new HashMap<>();

    private final ConcurrentSkipListSet<IaikP11Identity> identities =
            new ConcurrentSkipListSet<>();

    private final P11ModuleConf moduleConf;

    private final Map<Integer, Set<Long>> slotIndexMechanismsMap = new ConcurrentHashMap<>();

    private final Map<Long, Set<Long>> slotIdMechanismsMap = new ConcurrentHashMap<>();

    private boolean lastRefreshSuccessful;

    private long lastRefresh;

    private IaikP11CryptService(
            final P11ModuleConf moduleConf)
    throws SignerException {
        this.moduleConf = moduleConf;
        refresh();
    }

    private synchronized boolean reconnect()
    throws SignerException {
        if (System.currentTimeMillis() - lastRefresh < MIN_RECONNECT_INTERVAL) {
            LOG.info("just refreshed within one minute, skip this reconnect()");
            return lastRefreshSuccessful;
        }

        lastRefresh = System.currentTimeMillis();
        IaikP11ModulePool.getInstance().removeModule(moduleConf.getName());

        refresh();
        return lastRefreshSuccessful;
    }

    @Override
    public synchronized void refresh()
    throws SignerException {
        IaikP11Module module;

        LOG.info("refreshing PKCS#11 module {}", moduleConf.getName());
        lastRefreshSuccessful = false;
        try {
            module = IaikP11ModulePool.getInstance().getModule(moduleConf);
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

        Set<IaikP11Identity> currentIdentifies = new HashSet<>();
        Map<P11SlotIdentifier, Set<Long>> currentSupportedMechanisms = new HashMap<>();
        P11MechanismRetriever mechRetriever = moduleConf.getP11MechanismRetriever();

        List<P11SlotIdentifier> slotIds = module.getSlotIdentifiers();
        for (P11SlotIdentifier slotId : slotIds) {
            IaikP11Slot slot;
            try {
                slot = module.getSlot(slotId);
                if (slot == null) {
                    LOG.warn("could not initialize slot " + slotId);
                    continue;
                }
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

            slot.refresh();
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
                currentIdentifies.add((IaikP11Identity) identity);
            }
        }

        this.identities.clear();
        this.identities.addAll(currentIdentifies);
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

        lastRefreshSuccessful = true;

        if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("initialized ").append(this.identities.size()).append(" PKCS#11 Keys:\n");
            for (IaikP11Identity identity : this.identities) {
                sb.append("\t(").append(identity.getEntityId());
                sb.append(", algo=").append(identity.getPublicKey().getAlgorithm()).append(")\n");
            }

            LOG.info(sb.toString());
        }

        LOG.info("refreshed PKCS#11 module {}", moduleConf.getName());
    } // method refresh

    @Override
    public boolean supportsMechanism(
            final P11SlotIdentifier slotId,
            final long mechanism) {
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

    @Override
    public byte[] sign(
            final P11EntityIdentifier entityId,
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws SignerException {
        if (!supportsMechanism(entityId.getSlotId(), mechanism)) {
            throw new SignerException("mechanism " + mechanism + " is not supported by slot "
                    + entityId.getSlotId());
        }

        checkState();

        try {
            return getNonNullIdentity(entityId).sign(mechanism, parameters, content);
        } catch (PKCS11RuntimeException ex) {
            final String message = "could not call identity.sign()";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            if (reconnect()) {
                return sign_noReconnect(mechanism, parameters, content, entityId);
            } else {
                throw new SignerException("PKCS11RuntimeException: " + ex.getMessage(), ex);
            }
        }
    }

    private byte[] sign_noReconnect(
            final long mechanism,
            final P11Params parameters,
            final byte[] content,
            final P11EntityIdentifier entityId)
    throws SignerException {
        return getNonNullIdentity(entityId).sign(mechanism, parameters, content);
    }

    @Override
    public PublicKey getPublicKey(
            final P11EntityIdentifier entityId)
    throws SignerException {
        IaikP11Identity identity = getIdentity(entityId);
        return (identity == null)
                ? null
                : identity.getPublicKey();
    }

    @Override
    public X509Certificate getCertificate(
            final P11EntityIdentifier entityId)
    throws SignerException {
        IaikP11Identity identity = getIdentity(entityId);
        return (identity == null)
                ? null
                : identity.getCertificate();
    }

    private IaikP11Identity getNonNullIdentity(
            final P11EntityIdentifier entityId)
    throws SignerException {
        IaikP11Identity identity = getIdentity(entityId);
        if (identity == null) {
            throw new SignerException("found no identity " + entityId);
        }
        return identity;
    }

    private IaikP11Identity getIdentity(
            final P11EntityIdentifier entityId) {
        ParamUtil.requireNonNull("entityId", entityId);

        for (IaikP11Identity identity : identities) {
            if (identity.match(entityId)) {
                return identity;
            }
        }

        return null;
    }

    private synchronized void checkState()
    throws SignerException {
        if (!lastRefreshSuccessful) {
            if (System.currentTimeMillis() - lastRefresh >= MIN_RECONNECT_INTERVAL) {
                reconnect();
            }
        }

        if (!lastRefreshSuccessful) {
            throw new SignerException("PKCS#11 module is not initialized");
        }
    }

    @Override
    public String toString() {
        return moduleConf.toString();
    }

    @Override
    public X509Certificate[] getCertificates(
            final P11EntityIdentifier entityId)
    throws SignerException {
        IaikP11Identity identity = getIdentity(entityId);
        return (identity == null)
                ? null
                : identity.getCertificateChain();
    }

    @Override
    public P11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException {
        List<P11SlotIdentifier> slotIds = new LinkedList<>();
        for (IaikP11Identity identity : identities) {
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
        for (IaikP11Identity identity : identities) {
            if (slotId.equals(identity.getEntityId().getSlotId())) {
                keyLabels.add(identity.getEntityId().getKeyId().getKeyLabel());
            }
        }

        return keyLabels.toArray(new String[0]);
    }

    public static synchronized IaikP11CryptService getInstance(
            final P11ModuleConf moduleConf)
    throws SignerException {
        synchronized (INSTANCES) {
            final String name = moduleConf.getName();
            IaikP11CryptService instance = INSTANCES.get(name);
            if (instance == null) {
                instance = new IaikP11CryptService(moduleConf);
                INSTANCES.put(name, instance);
            }

            return instance;
        }
    }

}
