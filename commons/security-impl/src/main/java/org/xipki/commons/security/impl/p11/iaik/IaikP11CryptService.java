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
 *
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnsupportedMechanismException;
import org.xipki.commons.security.api.p11.parameters.P11Params;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

final class IaikP11CryptService implements P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(IaikP11CryptService.class);

    private static final Map<String, IaikP11CryptService> INSTANCES = new HashMap<>();

    private final P11ModuleConf moduleConf;

    private IaikP11Module module;

    private IaikP11CryptService(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        this.moduleConf = moduleConf;
        refresh();
    }

    @Override
    public synchronized void refresh()
    throws P11TokenException {
        LOG.info("refreshing PKCS#11 module {}", moduleConf.getName());
        IaikP11Module module = IaikP11ModulePool.getInstance().getModule(moduleConf);

        List<P11SlotIdentifier> slotIds = module.getSlotIdentifiers();
        for (P11SlotIdentifier slotId : slotIds) {
            P11Slot slot;
            try {
                slot = module.getSlot(slotId);
            } catch (P11TokenException ex) {
                final String message = "P11TokenException while initializing slot " + slotId;
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
        }

        LOG.info("refreshed PKCS#11 module {}", moduleConf.getName());
    } // method refresh

    @Override
    public Set<Long> getMechanisms(
            final P11SlotIdentifier slotId)
    throws P11TokenException {
        return module.getSlot(slotId).getMechanisms();
    }

    @Override
    public boolean supportsMechanism(
            final P11SlotIdentifier slotId,
            final long mechanism)
    throws P11TokenException {
        return module.getSlot(slotId).supportsMechanism(mechanism);
    }

    @Override
    public byte[] sign(
            final P11EntityIdentifier entityId,
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws P11TokenException, SecurityException {
        if (!supportsMechanism(entityId.getSlotId(), mechanism)) {
            throw new P11UnsupportedMechanismException(mechanism, entityId.getSlotId());
        }
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

    private P11Identity getNonnullIdentity(
            final P11EntityIdentifier entityId)
    throws P11TokenException {
        ParamUtil.requireNonNull("entityId", entityId);
        return module.getSlot(entityId.getSlotId()).getIdentity(entityId.getKeyId());
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

    static synchronized IaikP11CryptService getInstance(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
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

    @Override
    public P11Module getModule()
    throws P11TokenException {
        return module;
    }

}
