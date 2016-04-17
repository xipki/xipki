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

package org.xipki.commons.security.pkcs11.internal.iaik;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.commons.security.api.p11.AbstractP11Module;
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IaikP11Module extends AbstractP11Module {

    private static final Logger LOG = LoggerFactory.getLogger(IaikP11Module.class);

    private Module module;

    private IaikP11Module(
            final Module module,
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        super(moduleConf);
        this.module = ParamUtil.requireNonNull("module", module);

        Slot[] slotList;
        try {
            boolean cardPresent = true;
            slotList = module.getSlotList(cardPresent);
        } catch (Throwable th) {
            final String msg = "could not getSlotList of module " + moduleConf.getName();
            LogUtil.error(LOG, th, msg);
            throw new P11TokenException(msg);
        }

        if (slotList == null || slotList.length == 0) {
            throw new P11TokenException("no slot with present card could be found");
        }

        StringBuilder msg = new StringBuilder();

        Set<P11Slot> slots = new HashSet<>();
        for (int i = 0; i < slotList.length; i++) {
            Slot slot = slotList[i];
            P11SlotIdentifier slotId = new P11SlotIdentifier(i, slot.getSlotID());
            if (!moduleConf.isSlotIncluded(slotId)) {
                LOG.info("skipped slot {}", slotId);
                continue;
            }

            if (LOG.isDebugEnabled()) {
                msg.append("--------------------Slot ").append(i).append("--------------------\n");
                msg.append("id: ").append(slot.getSlotID()).append("\n");
                try {
                    msg.append(slot.getSlotInfo()).append("\n");
                } catch (TokenException ex) {
                    msg.append("error: " + ex.getMessage());
                }
            }

            List<char[]> pwd;
            try {
                pwd = moduleConf.getPasswordRetriever().getPassword(slotId);
            } catch (PasswordResolverException ex) {
                throw new P11TokenException("PasswordResolverException: " + ex.getMessage(), ex);
            }
            P11Slot p11Slot = new IaikP11Slot(moduleConf.getName(), slotId, slot,
                    moduleConf.isReadOnly(), moduleConf.getUserType(), pwd,
                    moduleConf.getMaxMessageSize(), moduleConf.getP11MechanismFilter());

            slots.add(p11Slot);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("{}", msg);
        }

        setSlots(slots);
    }

    public static P11Module getInstance(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        ParamUtil.requireNonNull("moduleConf", moduleConf);

        Module module;

        try {
            module = Module.getInstance(moduleConf.getNativeLibrary());
        } catch (IOException ex) {
            final String msg = "could not load the PKCS#11 module " + moduleConf.getName();
            LogUtil.error(LOG, ex, msg);
            throw new P11TokenException(msg, ex);
        }

        try {
            module.initialize(new DefaultInitializeArgs());
        } catch (PKCS11Exception ex) {
            if (ex.getErrorCode() != PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                LogUtil.error(LOG, ex);
                close(moduleConf.getName(), module);
                throw new P11TokenException(ex.getMessage(), ex);
            } else {
                LOG.info("PKCS#11 module already initialized");
                if (LOG.isInfoEnabled()) {
                    try {
                        LOG.info("pkcs11.getInfo():\n{}", module.getInfo());
                    } catch (TokenException e2) {
                        LOG.debug("module.getInfo()", e2);
                    }
                }
            }
        } catch (Throwable th) {
            LogUtil.error(LOG, th, "unexpected Exception");
            close(moduleConf.getName(), module);
            throw new P11TokenException(th.getMessage());
        }

        return new IaikP11Module(module, moduleConf);
    }

    @Override
    public void close() {
        for (P11SlotIdentifier slotId : getSlotIdentifiers()) {
            try {
                getSlot(slotId).close();
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not close PKCS#11 slot " + slotId);
            }
        }

        close(conf.getNativeLibrary(), module);
    }

    private static void close(
            final String modulePath,
            final Module module) {
        if (module == null) {
            return;
        }

        LOG.info("close", "close pkcs11 module: {}", modulePath);
        try {
            module.finalize(null);
        } catch (Throwable th) {
            LogUtil.error(LOG, th, "could not clonse module " + modulePath);
        }
    }
}
