/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.security.p11.keystore;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class KeystoreP11CryptService implements P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11CryptService.class);

    private final P11ModuleConf moduleConf;

    private KeystoreP11Module module;

    private static final Map<String, KeystoreP11CryptService> instances = new HashMap<>();

    public KeystoreP11CryptService(
            final P11ModuleConf moduleConf)
    throws SignerException {
        ParamUtil.assertNotNull("moduleConf", moduleConf);
        this.moduleConf = moduleConf;
        refresh();
    }

    private final ConcurrentSkipListSet<KeystoreP11Identity> identities
        = new ConcurrentSkipListSet<>();

    @Override
    public synchronized void refresh()
    throws SignerException {
        LOG.info("Refreshing PKCS#11 module {}", moduleConf.getName());
        try {
            this.module = KeystoreP11ModulePool.getInstance().getModule(moduleConf);
        } catch (SignerException e) {
            final String message = "could not initialize the PKCS#11 Module for "
                    + moduleConf.getName();
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            throw e;
        }

        Set<KeystoreP11Identity> currentIdentifies = new HashSet<>();

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
            } catch (SignerException e) {
                final String message = "SignerException while initializing slot " + slotId;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);
                continue;
            } catch (Throwable t) {
                final String message = "unexpected error while initializing slot " + slotId;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                            t.getMessage());
                }
                LOG.debug(message, t);
                continue;
            }

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

        if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("initialized ").append(this.identities.size()).append(" PKCS#11 Keys:\n");
            for (KeystoreP11Identity identity : this.identities) {
                sb.append("\t(slot ").append(identity.getSlotId());
                sb.append(", algo=").append(identity.getPublicKey().getAlgorithm());
                sb.append(", key=").append(identity.getKeyId()).append(")\n");
            }

            LOG.info(sb.toString());
        }

        LOG.info("refreshed PKCS#11 module {}", moduleConf.getName());
    } // method refresh

    @Override
    public byte[] CKM_RSA_PKCS(
            final byte[] encodedDigestInfo,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("Found no key with " + keyId);
        }

        return identity.CKM_RSA_PKCS(encodedDigestInfo);
    }

    @Override
    public byte[] CKM_RSA_X509(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_RSA_X509(hash);
    }

    @Override
    public byte[] CKM_ECDSA_X962(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_ECDSA_X962(hash);
    }

    @Override
    public byte[] CKM_ECDSA_Plain(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_ECDSA(hash);
    }

    @Override
    public byte[] CKM_DSA_X962(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_DSA_X962(hash);
    }

    @Override
    public byte[] CKM_DSA_Plain(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        if (identity == null) {
            throw new SignerException("found no key with " + keyId);
        }

        return identity.CKM_DSA(hash);
    }

    @Override
    public PublicKey getPublicKey(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        return (identity == null)
                ? null
                : identity.getPublicKey();
    }

    @Override
    public X509Certificate getCertificate(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        return (identity == null)
                ? null
                : identity.getCertificate();
    }

    @Override
    public X509Certificate[] getCertificates(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        KeystoreP11Identity identity = getIdentity(slotId, keyId);
        return (identity == null)
                ? null
                : identity.getCertificateChain();
    }

    @Override
    public P11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException {
        List<P11SlotIdentifier> slotIds = new LinkedList<>();
        for (KeystoreP11Identity identity : identities) {
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
        for (KeystoreP11Identity identity : identities) {
            if (slotId.equals(identity.getSlotId())) {
                keyLabels.add(identity.getKeyId().getKeyLabel());
            }
        }

        return keyLabels.toArray(new String[0]);
    }

    private KeystoreP11Identity getIdentity(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        if (keyId.getKeyLabel() == null) {
            throw new SignerException("only key referencing by key-label is supported");
        }

        for (KeystoreP11Identity identity : identities) {
            if (identity.match(slotId, keyId)) {
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
        synchronized (instances) {
            final String name = moduleConf.getName();
            KeystoreP11CryptService instance = instances.get(name);
            if (instance == null) {
                instance = new KeystoreP11CryptService(moduleConf);
                instances.put(name, instance);
            }

            return instance;
        }
    }

}
