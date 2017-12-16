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

package org.xipki.ca.server.mgmt.shell;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.completer.CaCrlReasonCompleter;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.common.util.DateUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "ca-revoke",
        description = "revoke CA")
@Service
public class CaRevokeCmd extends CaCommandSupport {

    public static final List<CrlReason> PERMITTED_REASONS = Collections.unmodifiableList(
            Arrays.asList(new CrlReason[] {
                CrlReason.UNSPECIFIED, CrlReason.KEY_COMPROMISE, CrlReason.CA_COMPROMISE,
                CrlReason.AFFILIATION_CHANGED, CrlReason.SUPERSEDED,
                CrlReason.CESSATION_OF_OPERATION,
                CrlReason.CERTIFICATE_HOLD, CrlReason.PRIVILEGE_WITHDRAWN}));

    @Argument(index = 0, name = "name", description = "CA name", required = true)
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--reason",
            required = true,
            description = "CRL reason\n"
                    + "(required)")
    @Completion(CaCrlReasonCompleter.class)
    private String reason;

    @Option(name = "--rev-date",
            description = "revocation date, UTC time of format yyyyMMddHHmmss\n"
                    + "(defaults to current time)")
    private String revocationDateS;

    @Option(name = "--inv-date",
            description = "invalidity date, UTC time of format yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    protected Object execute0() throws Exception {
        CrlReason crlReason = CrlReason.forNameOrText(reason);

        if (!PERMITTED_REASONS.contains(crlReason)) {
            throw new IllegalCmdParamException("reason " + reason + " is not permitted");
        }

        if (!caManager.getCaNames().contains(caName)) {
            throw new IllegalCmdParamException("invalid CA name " + caName);
        }

        Date revocationDate = null;
        revocationDate = isNotBlank(revocationDateS)
                ? DateUtil.parseUtcTimeyyyyMMddhhmmss(revocationDateS) : new Date();

        Date invalidityDate = null;
        if (isNotBlank(invalidityDateS)) {
            invalidityDate = DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
        }

        CertRevocationInfo revInfo = new CertRevocationInfo(crlReason, revocationDate,
                invalidityDate);
        boolean bo = caManager.revokeCa(caName, revInfo);
        output(bo, "revoked", "could not revoke", "CA " + caName);
        return null;
    } // method execute0

}
