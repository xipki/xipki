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
import org.xipki.common.util.ParamUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11NewKeyControl;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.shell.KeyGenAction;
import org.xipki.security.shell.completer.P11ModuleNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11KeyGenAction extends KeyGenAction {

    @Option(name = "--label", required = true,
            description = "label of the PKCS#11 objects\n(required)")
    protected String label;

    @Option(name = "--extractable", aliases = {"-x"},
            description = "whether the key is extractable")
    private Boolean extractable;

    @Option(name = "--slot", required = true,
            description = "slot index\n(required)")
    private Integer slotIndex;

    @Option(name = "--module",
            description = "Name of the PKCS#11 module.")
    @Completion(P11ModuleNameCompleter.class)
    private String moduleName = DEFAULT_P11MODULE_NAME;

    protected abstract boolean getDefaultExtractable();

    protected void finalize(final String keyType, final P11ObjectIdentifier objectId)
            throws Exception {
        ParamUtil.requireNonNull("objectId", objectId);
        println("generated " + keyType + " key " + objectId);
    }

    protected P11Slot getSlot()
            throws XiSecurityException, P11TokenException, IllegalCmdParamException {
        return getSlot(moduleName, slotIndex);
    }

    protected P11NewKeyControl getControl() {
        P11NewKeyControl control = new P11NewKeyControl();
        control.setExtractable((extractable == null)
                ? getDefaultExtractable() : extractable.booleanValue());
        return control;
    }

}
