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
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.password.api.PasswordResolverException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11PasswordsRetriever {

    private static final class SingleRetriever {

        private final Set<P11SlotIdFilter> slots;

        private final List<String> passwords;

        private SingleRetriever(
                final Set<P11SlotIdFilter> slots,
                final List<String> passwords) {
            this.slots = slots;
            if (CollectionUtil.isEmpty(passwords)) {
                this.passwords = null;
            } else {
                this.passwords = passwords;
            }
        }

        public boolean match(
                final P11SlotIdentifier slot) {
            if (slots == null) {
                return true;
            }
            for (P11SlotIdFilter m : slots) {
                if (m.match(slot)) {
                    return true;
                }
            }

            return false;
        }

        public List<char[]> getPasswords(
                final PasswordResolver passwordResolver)
        throws PasswordResolverException {
            if (passwords == null) {
                return null;
            }

            List<char[]> ret = new ArrayList<char[]>(passwords.size());
            for (String password : passwords) {
                if (passwordResolver == null) {
                    ret.add(password.toCharArray());
                } else {
                    ret.add(passwordResolver.resolvePassword(password));
                }
            }

            return ret;
        }

    } // class SingleRetriever

    private final List<SingleRetriever> singleRetrievers;
    private PasswordResolver passwordResolver;

    P11PasswordsRetriever() {
        singleRetrievers = new LinkedList<>();
    }

    void addPasswordEntry(
            final Set<P11SlotIdFilter> slots,
            final List<String> passwords) {
        singleRetrievers.add(new SingleRetriever(slots, passwords));
    }

    public List<char[]> getPassword(
            final P11SlotIdentifier slotId)
    throws PasswordResolverException {
        ParamUtil.requireNonNull("slotId", slotId);
        if (CollectionUtil.isEmpty(singleRetrievers)) {
            return null;
        }

        for (SingleRetriever sr : singleRetrievers) {
            if (sr.match(slotId)) {
                return sr.getPasswords(passwordResolver);
            }
        }

        return null;
    }

    public PasswordResolver getPasswordResolver() {
        return passwordResolver;
    }

    public void setPasswordResolver(
            final PasswordResolver passwordResolver) {
        this.passwordResolver = passwordResolver;
    }

}
