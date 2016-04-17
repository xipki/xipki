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

package org.xipki.commons.security.pkcs11.internal.emulator;

import java.io.File;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.commons.security.api.exception.P11TokenException;
import org.xipki.commons.security.api.p11.AbstractP11Module;
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EmulatorP11Module extends AbstractP11Module {

    public static final String PREFIX = "emulator:";

    private static final Logger LOG = LoggerFactory.getLogger(EmulatorP11Module.class);

    private EmulatorP11Module(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        super(moduleConf);
        final String modulePath = moduleConf.getNativeLibrary();
        if (!StringUtil.startsWithIgnoreCase(modulePath, PREFIX)) {
            throw new IllegalArgumentException("the module path does not starts with " + PREFIX
                    + ": " + modulePath);
        }

        File baseDir = new File(IoUtil.expandFilepath(modulePath.substring(PREFIX.length())));
        File[] children = baseDir.listFiles();

        if (children == null || children.length == 0) {
            LOG.error("found no slots");
            setSlots(Collections.emptySet());
            return;
        }

        Set<Integer> allSlotIndexes = new HashSet<>();
        Set<Long> allSlotIdentifiers = new HashSet<>();

        List<P11SlotIdentifier> slotIds = new LinkedList<>();

        for (File child : children) {
            if ((child.isDirectory() && child.canRead() && !child.exists())) {
                LOG.warn("ignore path {}, it does not point to a readable exist directory",
                        child.getPath());
                continue;
            }

            String filename = child.getName();
            String[] tokens = filename.split("-");
            if (tokens == null || tokens.length != 2) {
                LOG.warn("ignore dir {}, invalid filename syntax", child.getPath());
                continue;
            }

            int slotIndex;
            long slotId;
            try {
                slotIndex = Integer.parseInt(tokens[0]);
                slotId = Long.parseLong(tokens[1]);
            } catch (NumberFormatException ex) {
                LOG.warn("ignore dir {}, invalid filename syntax", child.getPath());
                continue;
            }

            if (allSlotIndexes.contains(slotIndex)) {
                LOG.error("ignore slot dir, the same slot index has been assigned", filename);
                continue;
            }

            if (allSlotIdentifiers.contains(slotId)) {
                LOG.error("ignore slot dir, the same slot identifier has been assigned", filename);
                continue;
            }

            allSlotIndexes.add(slotIndex);
            allSlotIdentifiers.add(slotId);

            P11SlotIdentifier slotIdentifier = new P11SlotIdentifier(slotIndex, slotId);
            if (!moduleConf.isSlotIncluded(slotIdentifier)) {
                LOG.info("skipped slot {}", slotId);
                continue;
            }

            slotIds.add(slotIdentifier);
        } // end for

        Set<P11Slot> slots = new HashSet<>();
        for (P11SlotIdentifier slotId : slotIds) {
            List<char[]> pwd;
            try {
                pwd = moduleConf.getPasswordRetriever().getPassword(slotId);
            } catch (PasswordResolverException ex) {
                throw new P11TokenException("PasswordResolverException: " + ex.getMessage(), ex);
            }

            File slotDir = new File(moduleConf.getNativeLibrary(), slotId.getIndex() + "-"
                    + slotId.getId());

            if (pwd == null) {
                throw new P11TokenException("no password is configured");
            }

            if (pwd.size() != 1) {
                throw new P11TokenException(pwd.size()
                        + " passwords are configured, but 1 is permitted");
            }

            PrivateKeyCryptor privateKeyCryptor = new PrivateKeyCryptor(pwd.get(0));

            int maxSessions = 20;
            P11Slot slot = new EmulatorP11Slot(moduleConf.getName(), slotDir, slotId,
                    moduleConf.isReadOnly(), privateKeyCryptor, moduleConf.getSecurityFactory(),
                    moduleConf.getP11MechanismFilter(), maxSessions);
            slots.add(slot);
        }

        setSlots(slots);
    } // constructor

    public static P11Module getInstance(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        ParamUtil.requireNonNull("moduleConf", moduleConf);
        return new EmulatorP11Module(moduleConf);
    }

    @Override
    public void close() {
        LOG.info("close", "close pkcs11 module: {}", getName());
    }

}
