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

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
@Command(scope = "xipki-tk", name = "update-cert",
        description = "update certificate in PKCS#11 device")
@Service
public class P11CertUpdateCmd extends P11SecurityCommandSupport {

    @Option(name = "--cert",
            required = true,
            description = "certificate file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
        P11Slot slot = getSlot();
        P11ObjectIdentifier objIdentifier = getObjectIdentifier();
        X509Certificate newCert = X509Util.parseCert(certFile);
        slot.updateCertificate(objIdentifier, newCert);
        println("updated certificate");
        return null;
    }

}
