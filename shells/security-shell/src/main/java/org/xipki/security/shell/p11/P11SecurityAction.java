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

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.shell.SecurityAction;
import org.xipki.security.shell.completer.P11ModuleNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11SecurityAction extends SecurityAction {

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
            throws IllegalCmdParamException, XiSecurityException, P11TokenException {
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
            throws XiSecurityException, P11TokenException, IllegalCmdParamException {
        return getSlot(moduleName, slotIndex);
    }

}
