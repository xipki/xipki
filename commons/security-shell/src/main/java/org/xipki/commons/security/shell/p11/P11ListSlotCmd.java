/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11WritableSlot;
import org.xipki.commons.security.shell.SecurityCommandSupport;
import org.xipki.commons.security.shell.completer.P11ModuleNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-tk", name = "list",
        description = "list objects in PKCS#11 device")
@Service
public class P11ListSlotCmd extends SecurityCommandSupport {

    @Option(name = "--verbose", aliases = "-v",
            description = "show object information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(name = "--module",
            description = "name of the PKCS#11 module.")
    @Completion(P11ModuleNameCompleter.class)
    private String moduleName = SecurityFactory.DEFAULT_P11MODULE_NAME;

    @Option(name = "--slot",
            description = "slot index")
    private Integer slotIndex;

    @Override
    protected Object doExecute()
    throws Exception {
        P11Module module = securityFactory.getP11Module(moduleName);
        if (module == null) {
            throw new IllegalCmdParamException("undefined module " + moduleName);
        }

        out("module: " + moduleName);
        List<P11SlotIdentifier> slots = module.getSlotIdentifiers();
        if (slotIndex == null) {
            output(slots);
            return null;
        }

        P11SlotIdentifier slotId = new P11SlotIdentifier(slotIndex, null);
        P11WritableSlot p11slot = module.getSlot(slotId);
        if (p11slot == null) {
            throw new IllegalCmdParamException("slot with index " + slotIndex + " does not exist");
        }

        p11slot.showDetails(System.out, verbose);
        System.out.flush();

        return null;
    }

    private void output(
            final List<P11SlotIdentifier> slots) {
        // list all slots
        final int n = slots.size();

        if (n == 0 || n == 1) {
            String numText = (n == 0)
                    ? "no"
                    : "1";
            out(numText + " slot is configured");
        } else {
            out(n + " slots are configured");
        }

        for (P11SlotIdentifier slotId : slots) {
            out("\tslot[" + slotId.getSlotIndex() + "]: " + slotId.getSlotId());
        }
    }

}
