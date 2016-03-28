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

package org.xipki.commons.security.api.p11;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.internal.p11.jaxb.MechanismsType;
import org.xipki.commons.security.api.internal.p11.jaxb.ModuleType;
import org.xipki.commons.security.api.internal.p11.jaxb.NativeLibraryType;
import org.xipki.commons.security.api.internal.p11.jaxb.PasswordType;
import org.xipki.commons.security.api.internal.p11.jaxb.PasswordsType;
import org.xipki.commons.security.api.internal.p11.jaxb.PermittedMechanismsType;
import org.xipki.commons.security.api.internal.p11.jaxb.SlotType;
import org.xipki.commons.security.api.internal.p11.jaxb.SlotsType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11ModuleConf {

    private static final Logger LOG = LoggerFactory.getLogger(P11ModuleConf.class);

    private final String name;

    private final String nativeLibrary;

    private final boolean readOnly;

    private final Set<P11SlotIdFilter> excludeSlots;

    private final Set<P11SlotIdFilter> includeSlots;

    private final P11PasswordRetriever passwordRetriever;

    private final P11MechanismFilter mechanismFilter;

    private final SecurityFactory securityFactory;

    private final int maxMessageSize;

    private final long userType;

    public P11ModuleConf(
            final ModuleType moduleType,
            final SecurityFactory securityFactory)
    throws InvalidConfException {
        ParamUtil.requireNonNull("moduleType", moduleType);
        this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);
        this.name = moduleType.getName();
        this.readOnly = moduleType.isReadonly();
        this.userType = moduleType.getUser().longValue();
        this.maxMessageSize = moduleType.getMaxMessageSize().intValue();
        if (maxMessageSize < 128) {
            throw new InvalidConfException("invalid maxMessageSize (< 128): " + maxMessageSize);
        }

        // Mechanism filter
        mechanismFilter = new P11MechanismFilter();
        PermittedMechanismsType mechsType = moduleType.getPermittedMechanisms();
        if (mechsType != null && CollectionUtil.isNonEmpty(mechsType.getMechanisms())) {
            for (MechanismsType mechType : mechsType.getMechanisms()) {
                Set<P11SlotIdFilter> slots = getSlotIdFilters(mechType.getSlots());
                Set<Long> mechanisms = new HashSet<>();
                for (String mechStr : mechType.getMechanism()) {
                    Long mech = null;
                    if (mechStr.startsWith("CKM_")) {
                        mech = P11Constants.getMechanism(mechStr);
                    } else {
                        int radix = 10;
                        String value = mechStr.toLowerCase();
                        if (value.startsWith("0x")) {
                            radix = 16;
                            value = value.substring(2);
                        }

                        if (value.endsWith("l")) {
                            value = value.substring(0, value.length() - 1);
                        }

                        try {
                            mech = Long.parseLong(value, radix);
                        } catch (NumberFormatException ex) {// CHECKSTYLE:SKIP
                        }
                    }

                    if (mech == null) {
                        LOG.warn("skipped unknown mechanism '" + mechStr + "'");
                    } else {
                        mechanisms.add(mech);
                    }
                }
                mechanismFilter.addEntry(slots, mechanisms);
            }
        }

        // Password retriever
        passwordRetriever = new P11PasswordRetriever();
        PasswordsType passwordsType = moduleType.getPasswords();
        if (passwordsType != null && CollectionUtil.isNonEmpty(passwordsType.getPassword())) {
            passwordRetriever.setPasswordResolver(securityFactory.getPasswordResolver());
            for (PasswordType passwordType : passwordsType.getPassword()) {
                Set<P11SlotIdFilter> slots = getSlotIdFilters(passwordType.getSlots());
                passwordRetriever.addPasswordEntry(slots,
                        new ArrayList<>(passwordType.getSinglePassword()));
            }
        }

        includeSlots = getSlotIdFilters(moduleType.getIncludeSlots());
        excludeSlots = getSlotIdFilters(moduleType.getExcludeSlots());

        final String osName = System.getProperty("os.name").toLowerCase();
        String nativeLibraryPath = null;
        for (NativeLibraryType library
                : moduleType.getNativeLibraries().getNativeLibrary()) {
            List<String> osNames = library.getOs();
            if (CollectionUtil.isEmpty(osNames)) {
                nativeLibraryPath = library.getPath();
            } else {
                for (String entry : osNames) {
                    if (osName.contains(entry.toLowerCase())) {
                        nativeLibraryPath = library.getPath();
                        break;
                    }
                }
            }

            if (nativeLibraryPath != null) {
                break;
            }
        } // end for (NativeLibraryType library)

        if (nativeLibraryPath == null) {
            throw new InvalidConfException("could not find PKCS#11 library for OS "
                    + osName);
        }
        this.nativeLibrary = nativeLibraryPath;
    }

    public String getName() {
        return name;
    }

    public String getNativeLibrary() {
        return nativeLibrary;
    }

    public int getMaxMessageSize() {
        return maxMessageSize;
    }

    public boolean isReadOnly() {
        return readOnly;
    }

    public long getUserType() {
        return userType;
    }

    public SecurityFactory getSecurityFactory() {
        return securityFactory;
    }

    public P11PasswordRetriever getPasswordRetriever() {
        return passwordRetriever;
    }

    public boolean isSlotIncluded(
            final P11SlotIdentifier slotId) {
        ParamUtil.requireNonNull("slotId", slotId);
        boolean included;
        if (CollectionUtil.isEmpty(includeSlots)) {
            included = true;
        } else {
            included = false;
            for (P11SlotIdFilter entry : includeSlots) {
                if (entry.match(slotId)) {
                    included = true;
                    break;
                }
            }
        }

        if (!included) {
            return false;
        }

        if (CollectionUtil.isEmpty(excludeSlots)) {
            return included;
        }

        for (P11SlotIdFilter entry : excludeSlots) {
            if (entry.match(slotId)) {
                return false;
            }
        }

        return true;
    }

    public P11MechanismFilter getP11MechanismFilter() {
        return mechanismFilter;
    }

    private static Set<P11SlotIdFilter> getSlotIdFilters(
            final SlotsType type)
    throws InvalidConfException {
        if (type == null || CollectionUtil.isEmpty(type.getSlot())) {
            return null;
        }

        Set<P11SlotIdFilter> filters = new HashSet<>();
        for (SlotType slotType : type.getSlot()) {
            Long slotId = null;
            if (slotType.getId() != null) {
                String str = slotType.getId().trim();
                try {
                    if (StringUtil.startsWithIgnoreCase(str, "0X")) {
                        slotId = Long.parseLong(str.substring(2), 16);
                    } else {
                        slotId = Long.parseLong(str);
                    }
                } catch (NumberFormatException ex) {
                    String message = "invalid slotId '" + str + "'";
                    LOG.error(message);
                    throw new InvalidConfException(message);
                }
            }
            filters.add(new P11SlotIdFilter(slotType.getIndex(), slotId));
        }

        return filters;
    }

}
