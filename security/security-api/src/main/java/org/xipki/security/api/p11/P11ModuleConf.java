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

package org.xipki.security.api.p11;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public class P11ModuleConf {

    private final String name;

    private final String nativeLibrary;

    private final Set<P11SlotIdentifier> excludeSlots;

    private final Set<P11SlotIdentifier> includeSlots;

    private final P11PasswordRetriever passwordRetriever;

    private final SecurityFactory securityFactory;

    public P11ModuleConf(
            final String name,
            final String nativeLibrary,
            final P11PasswordRetriever passwordRetriever,
            final SecurityFactory securityFactory) {
        this(name, nativeLibrary, passwordRetriever, null, null, securityFactory);
    }

    public P11ModuleConf(
            final String name,
            final String nativeLibrary,
            final P11PasswordRetriever passwordRetriever,
            final Set<P11SlotIdentifier> includeSlots,
            final Set<P11SlotIdentifier> excludeSlots,
            final SecurityFactory securityFactory) {
        ParamUtil.assertNotBlank("name", name);
        ParamUtil.assertNotBlank("nativeLibrary", nativeLibrary);
        ParamUtil.assertNotNull("securityFactory", securityFactory);

        this.name = name.toLowerCase();
        this.nativeLibrary = nativeLibrary;
        this.securityFactory = securityFactory;
        this.passwordRetriever = (passwordRetriever == null)
                ? P11NullPasswordRetriever.INSTANCE
                : passwordRetriever;

        Set<P11SlotIdentifier> set = new HashSet<>();
        if (includeSlots != null) {
            set.addAll(includeSlots);
        }
        this.includeSlots = Collections.unmodifiableSet(set);

        set = new HashSet<>();
        if (excludeSlots != null) {
            set.addAll(excludeSlots);
        }
        this.excludeSlots = Collections.unmodifiableSet(set);
    }

    public String getName() {
        return name;
    }

    public String getNativeLibrary() {
        return nativeLibrary;
    }

    public SecurityFactory getSecurityFactory() {
        return securityFactory;
    }

    public Set<P11SlotIdentifier> getExcludeSlots() {
        return excludeSlots;
    }

    public Set<P11SlotIdentifier> getIncludeSlots() {
        return includeSlots;
    }

    public P11PasswordRetriever getPasswordRetriever() {
        return passwordRetriever;
    }

    public boolean isSlotIncluded(
            final P11SlotIdentifier slot) {
        boolean included;
        if (CollectionUtil.isEmpty(includeSlots)) {
            included = true;
        } else {
            included = false;
            for (P11SlotIdentifier _slot : includeSlots) {
                if (_slot.equals(slot)) {
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

        for (P11SlotIdentifier _slot : excludeSlots) {
            if (_slot.equals(slot)) {
                return false;
            }
        }

        return true;
    }

}
