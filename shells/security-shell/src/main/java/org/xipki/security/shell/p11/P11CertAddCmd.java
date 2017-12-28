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

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.shell.SecurityAction;
import org.xipki.security.shell.completer.P11ModuleNameCompleter;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "add-cert-p11",
        description = "add certificate to PKCS#11 device")
@Service
public class P11CertAddCmd extends SecurityAction {

    @Option(name = "--slot", required = true,
            description = "slot index\n(required)")
    private Integer slotIndex;

    @Option(name = "--cert", required = true,
            description = "certificate file\n(required)")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(name = "--module",
            description = "name of the PKCS#11 module.")
    @Completion(P11ModuleNameCompleter.class)
    private String moduleName = DEFAULT_P11MODULE_NAME;

    @Override
    protected Object execute0() throws Exception {
        X509Certificate cert = X509Util.parseCert(certFile);
        P11Slot slot = getSlot(moduleName, slotIndex);
        P11ObjectIdentifier objectId = slot.addCert(cert);
        println("added certificate under " + objectId);
        return null;
    }

}
