/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.completer.CACRLReasonCompleter;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "ca-revoke", description="Revoke CA")
@Service
public class CaRevokeCommand extends CaCommand
{
    public static List<CRLReason> permitted_reasons = Collections.unmodifiableList(
            Arrays.asList(    new CRLReason[]
            {
                CRLReason.UNSPECIFIED, CRLReason.KEY_COMPROMISE, CRLReason.CA_COMPROMISE,
                CRLReason.AFFILIATION_CHANGED, CRLReason.SUPERSEDED, CRLReason.CESSATION_OF_OPERATION,
                CRLReason.CERTIFICATE_HOLD,    CRLReason.PRIVILEGE_WITHDRAWN}));

    @Argument(index = 0, name = "name", description = "CA name", required = true)
    @Completion(CaNameCompleter.class)
    protected String caName;

    @Option(name = "-reason",
            required = true,
            description = "Required. Reason, valid values are \n" +
                    "0: unspecified\n" +
                    "1: keyCompromise\n" +
                    "2: cACompromise\n" +
                    "3: affiliationChanged\n" +
                    "4: superseded\n" +
                    "5: cessationOfOperation\n" +
                    "6: certificateHold\n" +
                    "9: privilegeWithdrawn")
    @Completion(CACRLReasonCompleter.class)
    protected String reason;

    @Override
    protected Object doExecute()
    throws Exception
    {

        CRLReason crlReason = CRLReason.getInstance(reason);
        if(crlReason == null)
        {
            throw new IllegalCmdParamException("invalid reason " + reason);
        }

        if(permitted_reasons.contains(crlReason) == false)
        {
            throw new IllegalCmdParamException("reason " + reason + " is not permitted");
        }

        if(caManager.getCaNames().contains(caName) == false)
        {
            throw new IllegalCmdParamException("invalid CA name " + caName);
        }

        CertRevocationInfo revInfo = new CertRevocationInfo(crlReason);
        caManager.revokeCa(caName, revInfo);

        out("revoked CA " + caName);

        return null;
    }
}
