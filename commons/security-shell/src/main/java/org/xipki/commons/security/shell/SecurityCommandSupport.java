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

package org.xipki.commons.security.shell;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11WritableSlot;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class SecurityCommandSupport extends XipkiCommandSupport {

    @Reference
    protected SecurityFactory securityFactory;

    protected P11Slot getP11Slot(
            final String moduleName,
            final int slotIndex)
    throws SecurityException, P11TokenException, IllegalCmdParamException {
        P11Module module = getP11Module(moduleName);
        P11SlotIdentifier slotId = module.getSlotIdForIndex(slotIndex);
        return module.getSlot(slotId);
    }

    protected P11WritableSlot getP11WritableSlot(
            final String moduleName,
            final int slotIndex)
    throws SecurityException, P11TokenException, IllegalCmdParamException {
        P11Slot slot = getP11Slot(moduleName, slotIndex);
        if (slot instanceof P11WritableSlot) {
            return (P11WritableSlot) slot;
        }
        throw new P11TokenException("the slot is not writable");
    }

    protected P11Module getP11Module(
            final String moduleName)
    throws SecurityException, P11TokenException, IllegalCmdParamException {
        P11CryptService p11Service = securityFactory.getP11CryptService(moduleName);
        if (p11Service == null) {
            throw new IllegalCmdParamException("undefined module " + moduleName);
        }
        return p11Service.getModule();
    }

    protected static char[] merge(char[][] parts) {
        int sum = 0;
        for (int i = 0; i < parts.length; i++) {
            sum += parts[i].length;
        }

        char[] ret = new char[sum];
        int destPos = 0;
        for (int i = 0; i < parts.length; i++) {
            char[] part = parts[i];
            System.arraycopy(parts, 0, ret, destPos, part.length);
            destPos += part.length;
        }
        return ret;
    }
}
