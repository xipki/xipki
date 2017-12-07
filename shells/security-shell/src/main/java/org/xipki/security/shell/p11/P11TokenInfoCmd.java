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

package org.xipki.security.shell.p11;

import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.shell.SecurityCommandSupport;
import org.xipki.security.shell.completer.P11ModuleNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "token-info-p11",
        description = "list objects in PKCS#11 device")
@Service
public class P11TokenInfoCmd extends SecurityCommandSupport {

    @Option(name = "--verbose", aliases = "-v",
            description = "show object information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(name = "--module",
            description = "name of the PKCS#11 module.")
    @Completion(P11ModuleNameCompleter.class)
    private String moduleName = DEFAULT_P11MODULE_NAME;

    @Option(name = "--slot",
            description = "slot index")
    private Integer slotIndex;

    @Override
    protected Object execute0() throws Exception {
        P11Module module = getP11Module(moduleName);
        println("module: " + moduleName);
        List<P11SlotIdentifier> slots = module.slotIdentifiers();
        if (slotIndex == null) {
            output(slots);
            return null;
        }

        P11Slot slot = getSlot(moduleName, slotIndex);
        slot.showDetails(System.out, verbose);
        System.out.println();
        System.out.flush();
        return null;
    }

    private void output(final List<P11SlotIdentifier> slots) {
        // list all slots
        final int n = slots.size();

        if (n == 0 || n == 1) {
            String numText = (n == 0) ? "no" : "1";
            println(numText + " slot is configured");
        } else {
            println(n + " slots are configured");
        }

        for (P11SlotIdentifier slotId : slots) {
            println("\tslot[" + slotId.index() + "]: " + slotId.id());
        }
    }

}
