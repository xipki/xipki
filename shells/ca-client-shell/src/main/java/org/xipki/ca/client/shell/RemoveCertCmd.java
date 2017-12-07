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

package org.xipki.ca.client.shell;

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.client.api.CertIdOrError;
import org.xipki.cmp.PkiStatusInfo;
import org.xipki.common.RequestResponseDebug;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "cmp-remove-cert",
        description = "remove certificate")
@Service
public class RemoveCertCmd extends UnRevRemoveCertCommandSupport {

    @Override
    protected Object execute0() throws Exception {
        if (!(certFile == null ^ getSerialNumber() == null)) {
            throw new IllegalCmdParamException("exactly one of cert and serial must be specified");
        }

        CertIdOrError certIdOrError;
        if (certFile != null) {
            X509Certificate cert = X509Util.parseCert(certFile);
            RequestResponseDebug debug = getRequestResponseDebug();
            try {
                certIdOrError = caClient.removeCert(caName, cert, debug);
            } finally {
                saveRequestResponse(debug);
            }
        } else {
            RequestResponseDebug debug = getRequestResponseDebug();
            try {
                certIdOrError = caClient.removeCert(caName, getSerialNumber(), debug);
            } finally {
                saveRequestResponse(debug);
            }
        }

        if (certIdOrError.error() != null) {
            PkiStatusInfo error = certIdOrError.error();
            throw new CmdFailure("removing certificate failed: " + error);
        } else {
            println("removed certificate");
        }
        return null;
    } // method execute0

}
