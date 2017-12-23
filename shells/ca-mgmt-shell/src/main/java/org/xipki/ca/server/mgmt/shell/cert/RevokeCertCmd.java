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

package org.xipki.ca.server.mgmt.shell.cert;

import java.util.Date;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.DateUtil;
import org.xipki.console.karaf.completer.ClientCrlReasonCompleter;
import org.xipki.security.CrlReason;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "revoke-cert",
        description = "revoke certificate")
@Service
public class RevokeCertCmd extends UnRevRmCertAction {

    @Option(name = "--reason", aliases = "-r",
            required = true,
            description = "CRL reason\n"
                    + "(required)")
    @Completion(ClientCrlReasonCompleter.class)
    private String reason;

    @Option(name = "--inv-date",
            description = "invalidity date, UTC time of format yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    protected Object execute0() throws Exception {
        CrlReason crlReason = CrlReason.forNameOrText(reason);

        if (!CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason)) {
            throw new InvalidConfException("reason " + reason + " is not permitted");
        }

        Date invalidityDate = null;
        if (isNotBlank(invalidityDateS)) {
            invalidityDate = DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
        }

        boolean successful = caManager.revokeCertificate(caName, getSerialNumber(), crlReason,
                invalidityDate);
        output(successful, "revoked", "could not revoke", "certificate");

        return null;
    }

}
