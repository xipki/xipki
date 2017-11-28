/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11.iaik;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.pkcs11.AbstractP11Module;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11ModuleConf;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
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

    private IaikP11Module(final Module module, final P11ModuleConf moduleConf)
            throws P11TokenException {
        super(moduleConf);
        this.module = ParamUtil.requireNonNull("module", module);

        Slot[] slotList;
        try {
            slotList = module.getSlotList(Module.SlotRequirement.ALL_SLOTS);
        } catch (Throwable th) {
            final String msg = "could not getSlotList of module " + moduleConf.name();
            LogUtil.error(LOG, th, msg);
            throw new P11TokenException(msg);
        }

        final int size = (slotList == null) ? 0 : slotList.length;
        if (size == 0) {
            throw new P11TokenException("no slot could be found");
        }

        for (int i = 0; i < size; i++) {
            Slot slot = slotList[i];
            SlotInfo slotInfo;
            try {
                slotInfo = slot.getSlotInfo();
            } catch (TokenException ex) {
                LOG.error("ignore slot[{}] (id={} with error", i, slot.getSlotID());
                slotList[i] = null;
                continue;
            }

            if (!slotInfo.isTokenPresent()) {
                slotList[i] = null;
                LOG.info("ignore slot[{}] (id={} without token", i, slot.getSlotID());
            }
        }

        StringBuilder msg = new StringBuilder();

        Set<P11Slot> slots = new HashSet<>();
        for (int i = 0; i < slotList.length; i++) {
            Slot slot = slotList[i];
            if (slot == null) {
                continue;
            }

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
                pwd = moduleConf.passwordRetriever().getPassword(slotId);
            } catch (PasswordResolverException ex) {
                throw new P11TokenException("PasswordResolverException: " + ex.getMessage(), ex);
            }
            P11Slot p11Slot = new IaikP11Slot(moduleConf.name(), slotId, slot,
                    moduleConf.isReadOnly(), moduleConf.userType(), pwd,
                    moduleConf.maxMessageSize(), moduleConf.p11MechanismFilter());

            slots.add(p11Slot);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("{}", msg);
        }

        setSlots(slots);
    }

    public static P11Module getInstance(final P11ModuleConf moduleConf) throws P11TokenException {
        ParamUtil.requireNonNull("moduleConf", moduleConf);

        Module module;

        try {
            module = Module.getInstance(moduleConf.nativeLibrary());
        } catch (IOException ex) {
            final String msg = "could not load the PKCS#11 module " + moduleConf.name();
            LogUtil.error(LOG, ex, msg);
            throw new P11TokenException(msg, ex);
        }

        try {
            module.initialize(new DefaultInitializeArgs());
        } catch (PKCS11Exception ex) {
            if (ex.getErrorCode() != PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                LogUtil.error(LOG, ex);
                close(moduleConf.name(), module);
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
            LOG.error("unexpected Exception", th);
            close(moduleConf.name(), module);
            throw new P11TokenException(th.getMessage());
        }

        return new IaikP11Module(module, moduleConf);
    }

    @Override
    public void close() {
        for (P11SlotIdentifier slotId : slotIdentifiers()) {
            try {
                getSlot(slotId).close();
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not close PKCS#11 slot " + slotId);
            }
        }

        close(conf.nativeLibrary(), module);
    }

    private static void close(final String modulePath, final Module module) {
        if (module == null) {
            return;
        }

        LOG.info("close", "close pkcs11 module: {}", modulePath);
        try {
            module.finalize(null);
        } catch (Throwable th) {
            LogUtil.error(LOG, th, "could not close module " + modulePath);
        }
    }
}
