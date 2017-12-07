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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.shell.completer.SecretKeyTypeCompleter;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "xi", name = "secretkey-p11",
        description = "generate secret key in PKCS#11 device")
@Service
// CHECKSTYLE:SKIP
public class P11SecretKeyGenCmd extends P11KeyGenCommandSupport {

    @Option(name = "--key-type",
            required = true,
            description = "keytype, current only AES, DES3 and GENERIC are supported\n"
                    + "(required)")
    @Completion(SecretKeyTypeCompleter.class)
    private String keyType;

    @Option(name = "--key-size",
            required = true,
            description = "keysize in bit.")
    private Integer keysize;

    @Override
    protected Object execute0() throws Exception {
        long p11KeyType;
        if ("AES".equalsIgnoreCase(keyType)) {
            p11KeyType = PKCS11Constants.CKK_AES;

        } else if ("DES3".equalsIgnoreCase(keyType)) {
            p11KeyType = PKCS11Constants.CKK_DES3;
        } else if ("GENERIC".equalsIgnoreCase(keyType)) {
            p11KeyType = PKCS11Constants.CKK_GENERIC_SECRET;
        } else {
            throw new IllegalCmdParamException("invalid keyType " + keyType);
        }

        P11Slot slot = getSlot();
        P11ObjectIdentifier objId = slot.generateSecretKey(p11KeyType, keysize, label,
                getControl());
        finalize("Generate Secret Key", objId);
        return null;
    }

    @Override
    protected boolean getDefaultExtractable() {
        return true;
    }

}
