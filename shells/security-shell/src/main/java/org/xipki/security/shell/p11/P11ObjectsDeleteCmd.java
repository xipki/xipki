/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.shell.SecurityAction;
import org.xipki.security.shell.completer.P11ModuleNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "delete-objects-p11",
        description = "delete objects in PKCS#11 device")
@Service
public class P11ObjectsDeleteCmd extends SecurityAction {

    @Option(name = "--slot",
            required = true,
            description = "slot index\n"
                    + "(required)")
    protected Integer slotIndex;

    @Option(name = "--id",
            description = "id (hex) of the objects in the PKCS#11 device\n"
                    + "at least one of id and label must be specified")
    private String id;

    @Option(name = "--label",
            description = "label of the objects in the PKCS#11 device\n"
                    + "at least one of id and label must be specified")
    private String label;

    @Option(name = "--module",
            description = "name of the PKCS#11 module")
    @Completion(P11ModuleNameCompleter.class)
    protected String moduleName = DEFAULT_P11MODULE_NAME;

    @Override
    protected Object execute0() throws Exception {
        P11Slot slot = getSlot(moduleName, slotIndex);
        byte[] idBytes = null;
        if (id != null) {
            idBytes = Hex.decode(id);
        }
        int num = slot.removeObjects(idBytes, label);
        println("deleted " + num + " objects");
        return null;
    }

}
