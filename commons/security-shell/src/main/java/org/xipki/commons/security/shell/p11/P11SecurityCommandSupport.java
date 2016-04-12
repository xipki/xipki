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

package org.xipki.commons.security.shell.p11;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.security.api.exception.SecurityException;
import org.xipki.commons.security.api.p11.P11ObjectIdentifier;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.shell.SecurityCommandSupport;
import org.xipki.commons.security.shell.completer.P11ModuleNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11SecurityCommandSupport extends SecurityCommandSupport {

    @Option(name = "--slot",
            required = true,
            description = "slot index\n"
                    + "(required)")
    protected Integer slotIndex;

    @Option(name = "--id",
            description = "id of the private key in the PKCS#11 device\n"
                    + "either keyId or keyLabel must be specified")
    protected String id;

    @Option(name = "--label",
            description = "label of the private key in the PKCS#11 device\n"
                    + "either keyId or keyLabel must be specified")
    protected String label;

    @Option(name = "--module",
            description = "name of the PKCS#11 module")
    @Completion(P11ModuleNameCompleter.class)
    protected String moduleName = DEFAULT_P11MODULE_NAME;

    public P11ObjectIdentifier getObjectIdentifier()
    throws IllegalCmdParamException, SecurityException, P11TokenException {
        P11Slot slot = getSlot();
        P11ObjectIdentifier objIdentifier;
        if (id != null && label == null) {
            objIdentifier = slot.getObjectIdForId(Hex.decode(id));
        } else if (id == null && label != null) {
            objIdentifier = slot.getObjectIdForLabel(label);
        } else {
            throw new IllegalCmdParamException(
                    "exactly one of keyId or keyLabel should be specified");
        }
        return objIdentifier;
    }

    protected P11Slot getSlot()
    throws SecurityException, P11TokenException, IllegalCmdParamException {
        return getSlot(moduleName, slotIndex);
    }

}
